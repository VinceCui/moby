// Package daemon exposes the functions that occur on the host server
// that the Docker daemon is running.
//
// In implementing the various functions of the daemon, there is often
// a method-specific struct for configuring the runtime behavior.
package daemon

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/errdefs"
	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/container"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/daemon/discovery"
	"github.com/docker/docker/daemon/events"
	"github.com/docker/docker/daemon/exec"
	"github.com/docker/docker/daemon/logger"
	"github.com/docker/docker/daemon/network"
	"github.com/sirupsen/logrus"
	// register graph drivers
	_ "github.com/docker/docker/daemon/graphdriver/register"
	"github.com/docker/docker/daemon/initlayer"
	"github.com/docker/docker/daemon/stats"
	dmetadata "github.com/docker/docker/distribution/metadata"
	"github.com/docker/docker/distribution/xfer"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/image"
	"github.com/docker/docker/layer"
	"github.com/docker/docker/libcontainerd"
	"github.com/docker/docker/migrate/v1"
	"github.com/docker/docker/pkg/containerfs"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/plugingetter"
	"github.com/docker/docker/pkg/sysinfo"
	"github.com/docker/docker/pkg/system"
	"github.com/docker/docker/pkg/truncindex"
	"github.com/docker/docker/plugin"
	pluginexec "github.com/docker/docker/plugin/executor/containerd"
	refstore "github.com/docker/docker/reference"
	"github.com/docker/docker/registry"
	"github.com/docker/docker/runconfig"
	volumedrivers "github.com/docker/docker/volume/drivers"
	"github.com/docker/docker/volume/local"
	"github.com/docker/docker/volume/store"
	"github.com/docker/libnetwork"
	"github.com/docker/libnetwork/cluster"
	nwconfig "github.com/docker/libnetwork/config"
	"github.com/docker/libtrust"
	"github.com/pkg/errors"
)

// MainNamespace is the name of the namespace used for users containers
const MainNamespace = "moby"

var (
	errSystemNotSupported = errors.New("the Docker daemon is not supported on this platform")
)

type daemonStore struct {
	graphDriver               string
	imageRoot                 string
	imageStore                image.Store
	layerStore                layer.Store
	distributionMetadataStore dmetadata.Store
}

// Daemon holds information about the Docker daemon.
type Daemon struct {
	ID                    string
	repository            string
	containers            container.Store
	containersReplica     container.ViewDB
	execCommands          *exec.Store
	downloadManager       *xfer.LayerDownloadManager
	uploadManager         *xfer.LayerUploadManager
	trustKey              libtrust.PrivateKey
	idIndex               *truncindex.TruncIndex
	configStore           *config.Config
	statsCollector        *stats.Collector
	defaultLogConfig      containertypes.LogConfig
	RegistryService       registry.Service
	EventsService         *events.Events
	netController         libnetwork.NetworkController
	volumes               *store.VolumeStore
	discoveryWatcher      discovery.Reloader
	root                  string
	seccompEnabled        bool
	apparmorEnabled       bool
	shutdown              bool
	idMappings            *idtools.IDMappings
	stores                map[string]daemonStore // By container target platform
	referenceStore        refstore.Store
	PluginStore           *plugin.Store // todo: remove
	pluginManager         *plugin.Manager
	linkIndex             *linkIndex
	containerd            libcontainerd.Client
	containerdRemote      libcontainerd.Remote
	defaultIsolation      containertypes.Isolation // Default isolation mode on Windows
	clusterProvider       cluster.Provider
	cluster               Cluster
	genericResources      []swarm.GenericResource
	metricsPluginListener net.Listener

	machineMemory uint64

	seccompProfile     []byte
	seccompProfilePath string

	diskUsageRunning int32
	pruneRunning     int32
	hosts            map[string]bool // hosts stores the addresses the daemon is listening on
	startupDone      chan struct{}

	attachmentStore network.AttachmentStore
}

// StoreHosts stores the addresses the daemon is listening on
func (daemon *Daemon) StoreHosts(hosts []string) {
	if daemon.hosts == nil {
		daemon.hosts = make(map[string]bool)
	}
	for _, h := range hosts {
		daemon.hosts[h] = true
	}
}

// HasExperimental returns whether the experimental features of the daemon are enabled or not
func (daemon *Daemon) HasExperimental() bool {
	return daemon.configStore != nil && daemon.configStore.Experimental
}

func (daemon *Daemon) restore() error {
	containers := make(map[string]*container.Container)

	logrus.Info("Loading containers: start.")

	dir, err := ioutil.ReadDir(daemon.repository)
	if err != nil {
		return err
	}

	//cyz-> daemon.repository存放当前运行的所有containers，这个for重置这些containers的rw layer
	for _, v := range dir {
		id := v.Name()
		//cyz-> 创建一个新的BaseContainer并从存储的hostconfig.json生成config，如果生成的container的id和原id不同，出错
		container, err := daemon.load(id)
		if err != nil {
			logrus.Errorf("Failed to load container %v: %v", id, err)
			continue
		}

		// Ignore the container if it does not support the current driver being used by the graph
		//cyz-> 看看Container的driver和现在所用的是否兼容
		currentDriverForContainerOS := daemon.stores[container.OS].graphDriver
		if (container.Driver == "" && currentDriverForContainerOS == "aufs") || container.Driver == currentDriverForContainerOS {
			rwlayer, err := daemon.stores[container.OS].layerStore.GetRWLayer(container.ID)
			if err != nil {
				logrus.Errorf("Failed to load container mount %v: %v", id, err)
				continue
			}
			container.RWLayer = rwlayer
			logrus.Debugf("Loaded container %v, isRunning: %v", container.ID, container.IsRunning())

			containers[container.ID] = container
		} else {
			logrus.Debugf("Cannot load container %s because it was created with another graph driver.", container.ID)
		}
	}

	removeContainers := make(map[string]*container.Container)
	restartContainers := make(map[*container.Container]chan struct{})
	activeSandboxes := make(map[string]interface{})
	for id, c := range containers {
		if err := daemon.registerName(c); err != nil {
			logrus.Errorf("Failed to register container name %s: %s", c.ID, err)
			delete(containers, id)
			continue
		}
		// verify that all volumes valid and have been migrated from the pre-1.7 layout
		if err := daemon.verifyVolumesInfo(c); err != nil {
			// don't skip the container due to error
			logrus.Errorf("Failed to verify volumes for container '%s': %v", c.ID, err)
		}
		if err := daemon.Register(c); err != nil {
			logrus.Errorf("Failed to register container %s: %s", c.ID, err)
			delete(containers, id)
			continue
		}

		// The LogConfig.Type is empty if the container was created before docker 1.12 with default log driver.
		// We should rewrite it to use the daemon defaults.
		// Fixes https://github.com/docker/docker/issues/22536
		if c.HostConfig.LogConfig.Type == "" {
			if err := daemon.mergeAndVerifyLogConfig(&c.HostConfig.LogConfig); err != nil {
				logrus.Errorf("Failed to verify log config for container %s: %q", c.ID, err)
				continue
			}
		}
	}

	var (
		wg      sync.WaitGroup
		mapLock sync.Mutex
	)
	for _, c := range containers {
		wg.Add(1)
		go func(c *container.Container) {
			defer wg.Done()
			daemon.backportMountSpec(c)
			if err := daemon.checkpointAndSave(c); err != nil {
				logrus.WithError(err).WithField("container", c.ID).Error("error saving backported mountspec to disk")
			}

			daemon.setStateCounter(c)

			logrus.WithFields(logrus.Fields{
				"container": c.ID,
				"running":   c.IsRunning(),
				"paused":    c.IsPaused(),
			}).Debug("restoring container")

			var (
				err      error
				alive    bool
				ec       uint32
				exitedAt time.Time
			)

			alive, _, err = daemon.containerd.Restore(context.Background(), c.ID, c.InitializeStdio)
			if err != nil && !errdefs.IsNotFound(err) {
				logrus.Errorf("Failed to restore container %s with containerd: %s", c.ID, err)
				return
			}
			if !alive {
				ec, exitedAt, err = daemon.containerd.DeleteTask(context.Background(), c.ID)
				if err != nil && !errdefs.IsNotFound(err) {
					logrus.WithError(err).Errorf("Failed to delete container %s from containerd", c.ID)
					return
				}
			}

			if c.IsRunning() || c.IsPaused() {
				c.RestartManager().Cancel() // manually start containers because some need to wait for swarm networking

				if c.IsPaused() && alive {
					s, err := daemon.containerd.Status(context.Background(), c.ID)
					if err != nil {
						logrus.WithError(err).WithField("container", c.ID).
							Errorf("Failed to get container status")
					} else {
						logrus.WithField("container", c.ID).WithField("state", s).
							Info("restored container paused")
						switch s {
						case libcontainerd.StatusPaused, libcontainerd.StatusPausing:
							// nothing to do
						case libcontainerd.StatusStopped:
							alive = false
						case libcontainerd.StatusUnknown:
							logrus.WithField("container", c.ID).
								Error("Unknown status for container during restore")
						default:
							// running
							c.Lock()
							c.Paused = false
							daemon.setStateCounter(c)
							if err := c.CheckpointTo(daemon.containersReplica); err != nil {
								logrus.WithError(err).WithField("container", c.ID).
									Error("Failed to update stopped container state")
							}
							c.Unlock()
						}
					}
				}

				if !alive {
					c.Lock()
					c.SetStopped(&container.ExitStatus{ExitCode: int(ec), ExitedAt: exitedAt})
					daemon.Cleanup(c)
					if err := c.CheckpointTo(daemon.containersReplica); err != nil {
						logrus.Errorf("Failed to update stopped container %s state: %v", c.ID, err)
					}
					c.Unlock()
				}

				// we call Mount and then Unmount to get BaseFs of the container
				if err := daemon.Mount(c); err != nil {
					// The mount is unlikely to fail. However, in case mount fails
					// the container should be allowed to restore here. Some functionalities
					// (like docker exec -u user) might be missing but container is able to be
					// stopped/restarted/removed.
					// See #29365 for related information.
					// The error is only logged here.
					logrus.Warnf("Failed to mount container on getting BaseFs path %v: %v", c.ID, err)
				} else {
					if err := daemon.Unmount(c); err != nil {
						logrus.Warnf("Failed to umount container on getting BaseFs path %v: %v", c.ID, err)
					}
				}

				c.ResetRestartManager(false)
				if !c.HostConfig.NetworkMode.IsContainer() && c.IsRunning() {
					options, err := daemon.buildSandboxOptions(c)
					if err != nil {
						logrus.Warnf("Failed build sandbox option to restore container %s: %v", c.ID, err)
					}
					mapLock.Lock()
					activeSandboxes[c.NetworkSettings.SandboxID] = options
					mapLock.Unlock()
				}
			} else {
				// get list of containers we need to restart

				// Do not autostart containers which
				// has endpoints in a swarm scope
				// network yet since the cluster is
				// not initialized yet. We will start
				// it after the cluster is
				// initialized.
				if daemon.configStore.AutoRestart && c.ShouldRestart() && !c.NetworkSettings.HasSwarmEndpoint {
					mapLock.Lock()
					restartContainers[c] = make(chan struct{})
					mapLock.Unlock()
				} else if c.HostConfig != nil && c.HostConfig.AutoRemove {
					mapLock.Lock()
					removeContainers[c.ID] = c
					mapLock.Unlock()
				}
			}

			c.Lock()
			if c.RemovalInProgress {
				// We probably crashed in the middle of a removal, reset
				// the flag.
				//
				// We DO NOT remove the container here as we do not
				// know if the user had requested for either the
				// associated volumes, network links or both to also
				// be removed. So we put the container in the "dead"
				// state and leave further processing up to them.
				logrus.Debugf("Resetting RemovalInProgress flag from %v", c.ID)
				c.RemovalInProgress = false
				c.Dead = true
				if err := c.CheckpointTo(daemon.containersReplica); err != nil {
					logrus.Errorf("Failed to update RemovalInProgress container %s state: %v", c.ID, err)
				}
			}
			c.Unlock()
		}(c)
	}
	wg.Wait()
	daemon.netController, err = daemon.initNetworkController(daemon.configStore, activeSandboxes)
	if err != nil {
		return fmt.Errorf("Error initializing network controller: %v", err)
	}

	// Now that all the containers are registered, register the links
	for _, c := range containers {
		if err := daemon.registerLinks(c, c.HostConfig); err != nil {
			logrus.Errorf("failed to register link for container %s: %v", c.ID, err)
		}
	}

	group := sync.WaitGroup{}
	for c, notifier := range restartContainers {
		group.Add(1)

		go func(c *container.Container, chNotify chan struct{}) {
			defer group.Done()

			logrus.Debugf("Starting container %s", c.ID)

			// ignore errors here as this is a best effort to wait for children to be
			//   running before we try to start the container
			children := daemon.children(c)
			timeout := time.After(5 * time.Second)
			for _, child := range children {
				if notifier, exists := restartContainers[child]; exists {
					select {
					case <-notifier:
					case <-timeout:
					}
				}
			}

			// Make sure networks are available before starting
			daemon.waitForNetworks(c)
			if err := daemon.containerStart(c, "", "", true); err != nil {
				logrus.Errorf("Failed to start container %s: %s", c.ID, err)
			}
			close(chNotify)
		}(c, notifier)

	}
	group.Wait()

	removeGroup := sync.WaitGroup{}
	for id := range removeContainers {
		removeGroup.Add(1)
		go func(cid string) {
			if err := daemon.ContainerRm(cid, &types.ContainerRmConfig{ForceRemove: true, RemoveVolume: true}); err != nil {
				logrus.Errorf("Failed to remove container %s: %s", cid, err)
			}
			removeGroup.Done()
		}(id)
	}
	removeGroup.Wait()

	// any containers that were started above would already have had this done,
	// however we need to now prepare the mountpoints for the rest of the containers as well.
	// This shouldn't cause any issue running on the containers that already had this run.
	// This must be run after any containers with a restart policy so that containerized plugins
	// can have a chance to be running before we try to initialize them.
	for _, c := range containers {
		// if the container has restart policy, do not
		// prepare the mountpoints since it has been done on restarting.
		// This is to speed up the daemon start when a restart container
		// has a volume and the volume driver is not available.
		if _, ok := restartContainers[c]; ok {
			continue
		} else if _, ok := removeContainers[c.ID]; ok {
			// container is automatically removed, skip it.
			continue
		}

		group.Add(1)
		go func(c *container.Container) {
			defer group.Done()
			if err := daemon.prepareMountPoints(c); err != nil {
				logrus.Error(err)
			}
		}(c)
	}

	group.Wait()

	logrus.Info("Loading containers: done.")

	return nil
}

// RestartSwarmContainers restarts any autostart container which has a
// swarm endpoint.
func (daemon *Daemon) RestartSwarmContainers() {
	group := sync.WaitGroup{}
	//cyz-> daemon.List()返回daemon的containers.List()
	for _, c := range daemon.List() {
		if !c.IsRunning() && !c.IsPaused() {
			// Autostart all the containers which has a
			// swarm endpoint now that the cluster is
			// initialized.
			if daemon.configStore.AutoRestart && c.ShouldRestart() && c.NetworkSettings.HasSwarmEndpoint {
				group.Add(1)
				go func(c *container.Container) {
					defer group.Done()
					if err := daemon.containerStart(c, "", "", true); err != nil {
						logrus.Error(err)
					}
				}(c)
			}
		}

	}
	group.Wait()
}

// waitForNetworks is used during daemon initialization when starting up containers
// It ensures that all of a container's networks are available before the daemon tries to start the container.
// In practice it just makes sure the discovery service is available for containers which use a network that require discovery.
func (daemon *Daemon) waitForNetworks(c *container.Container) {
	if daemon.discoveryWatcher == nil {
		return
	}
	// Make sure if the container has a network that requires discovery that the discovery service is available before starting
	for netName := range c.NetworkSettings.Networks {
		// If we get `ErrNoSuchNetwork` here, we can assume that it is due to discovery not being ready
		// Most likely this is because the K/V store used for discovery is in a container and needs to be started
		if _, err := daemon.netController.NetworkByName(netName); err != nil {
			if _, ok := err.(libnetwork.ErrNoSuchNetwork); !ok {
				continue
			}
			// use a longish timeout here due to some slowdowns in libnetwork if the k/v store is on anything other than --net=host
			// FIXME: why is this slow???
			logrus.Debugf("Container %s waiting for network to be ready", c.Name)
			select {
			case <-daemon.discoveryWatcher.ReadyCh():
			case <-time.After(60 * time.Second):
			}
			return
		}
	}
}

func (daemon *Daemon) children(c *container.Container) map[string]*container.Container {
	return daemon.linkIndex.children(c)
}

// parents returns the names of the parent containers of the container
// with the given name.
func (daemon *Daemon) parents(c *container.Container) map[string]*container.Container {
	return daemon.linkIndex.parents(c)
}

func (daemon *Daemon) registerLink(parent, child *container.Container, alias string) error {
	fullName := path.Join(parent.Name, alias)
	if err := daemon.containersReplica.ReserveName(fullName, child.ID); err != nil {
		if err == container.ErrNameReserved {
			logrus.Warnf("error registering link for %s, to %s, as alias %s, ignoring: %v", parent.ID, child.ID, alias, err)
			return nil
		}
		return err
	}
	daemon.linkIndex.link(parent, child, fullName)
	return nil
}

// DaemonJoinsCluster informs the daemon has joined the cluster and provides
// the handler to query the cluster component
func (daemon *Daemon) DaemonJoinsCluster(clusterProvider cluster.Provider) {
	daemon.setClusterProvider(clusterProvider)
}

// DaemonLeavesCluster informs the daemon has left the cluster
func (daemon *Daemon) DaemonLeavesCluster() {
	// Daemon is in charge of removing the attachable networks with
	// connected containers when the node leaves the swarm
	daemon.clearAttachableNetworks()
	// We no longer need the cluster provider, stop it now so that
	// the network agent will stop listening to cluster events.
	daemon.setClusterProvider(nil)
	// Wait for the networking cluster agent to stop
	daemon.netController.AgentStopWait()
	// Daemon is in charge of removing the ingress network when the
	// node leaves the swarm. Wait for job to be done or timeout.
	// This is called also on graceful daemon shutdown. We need to
	// wait, because the ingress release has to happen before the
	// network controller is stopped.
	if done, err := daemon.ReleaseIngress(); err == nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			logrus.Warnf("timeout while waiting for ingress network removal")
		}
	} else {
		logrus.Warnf("failed to initiate ingress network removal: %v", err)
	}

	daemon.attachmentStore.ClearAttachments()
}

// setClusterProvider sets a component for querying the current cluster state.
func (daemon *Daemon) setClusterProvider(clusterProvider cluster.Provider) {
	daemon.clusterProvider = clusterProvider
	daemon.netController.SetClusterProvider(clusterProvider)
}

// IsSwarmCompatible verifies if the current daemon
// configuration is compatible with the swarm mode
func (daemon *Daemon) IsSwarmCompatible() error {
	if daemon.configStore == nil {
		return nil
	}
	return daemon.configStore.IsSwarmCompatible()
}

// NewDaemon sets up everything for the daemon to be able to service
// requests from the webserver.
func NewDaemon(config *config.Config, registryService registry.Service, containerdRemote libcontainerd.Remote, pluginStore *plugin.Store) (daemon *Daemon, err error) {
	
	setDefaultMtu(config)

	// Ensure that we have a correct root key limit for launching containers.
	//cyz-> root key是啥,此处存疑？？？
	if err := ModifyRootKeyLimit(); err != nil {
		logrus.Warnf("unable to modify root key limit, number of containers could be limited by this quota: %v", err)
	}

	// Ensure we have compatible and valid configuration options
	if err := verifyDaemonSettings(config); err != nil {
		return nil, err
	}

	// Do we have a disabled network?
	config.DisableBridge = isBridgeNetworkDisabled(config)

	// Verify the platform is supported as a daemon
	if !platformSupported {
		return nil, errSystemNotSupported
	}

	// Validate platform-specific requirements
	//cyz-> 此时如果不是root，则会出错。
	if err := checkSystem(); err != nil {
		return nil, err
	}

	//cyz-> 设置remaproot，可以让容器有一个 “假”的  root 用户，它在容器内是 root，在容器外是一个非 root 用户。
	idMappings, err := setupRemappedRoot(config)
	if err != nil {
		return nil, err
	}
	//cyz-> 获得容器的root映射到host的uid，gid，如果idMappings，则返回0,0表示不使用user remap，也正确。
	rootIDs := idMappings.RootPair()
	//cyz-> 设置Daemon进程的一些配置，oom_score_adj，may_detach_mounts，此处存疑？？？
	if err := setupDaemonProcess(config); err != nil {
		return nil, err
	}

	// set up the tmpDir to use a canonical path
	tmp, err := prepareTempDir(config.Root, rootIDs)
	if err != nil {
		return nil, fmt.Errorf("Unable to get the TempDir under %s: %s", config.Root, err)
	}
	realTmp, err := getRealPath(tmp)
	if err != nil {
		return nil, fmt.Errorf("Unable to get the full path to the TempDir (%s): %s", tmp, err)
	}
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(realTmp); err != nil && os.IsNotExist(err) {
			if err := system.MkdirAll(realTmp, 0700, ""); err != nil {
				return nil, fmt.Errorf("Unable to create the TempDir (%s): %s", realTmp, err)
			}
		}
		os.Setenv("TEMP", realTmp)
		os.Setenv("TMP", realTmp)
	} else {
		os.Setenv("TMPDIR", realTmp)
	}

	d := &Daemon{
		configStore: config,
		PluginStore: pluginStore,
		startupDone: make(chan struct{}),
	}
	// Ensure the daemon is properly shutdown if there is a failure during
	// initialization
	defer func() {
		if err != nil {
			if err := d.Shutdown(); err != nil {
				logrus.Error(err)
			}
		}
	}()

	//cyz-> 根据conf相关配置设置Generic Resources，此处存疑？？？
	if err := d.setGenericResources(config); err != nil {
		return nil, err
	}
	// set up SIGUSR1 handler on Unix-like systems, or a Win32 global event
	// on Windows to dump Go routine stacks
	//cyz-> 监听SIGUSR1信号，一旦发生，保存stack trace到指定目录下的1个file（当前时间命名）
	stackDumpDir := config.Root
	if execRoot := config.GetExecRoot(); execRoot != "" {
		stackDumpDir = execRoot
	}
	d.setupDumpStackTrap(stackDumpDir)

	/*cyz-> 设置seccomp的profile
		secure computing mode请参考资料https://docs.docker.com/engine/security/seccomp/#run-without-the-default-seccomp-profile
		seccomp特性和user remap特性是docker实现安全的两个特性，在《Docker技术入门与实战》中有所说明*/
	if err := d.setupSeccompProfile(); err != nil {
		return nil, err
	}

	// Set the default isolation mode (only applicable on Windows)
	if err := d.setDefaultIsolation(); err != nil {
		return nil, fmt.Errorf("error setting default isolation mode: %v", err)
	}

	logrus.Debugf("Using default logging driver %s", config.LogConfig.Type)

	//cyz-> kernel setting的90%
	if err := configureMaxThreads(config); err != nil {
		logrus.Warnf("Failed to configure golang's threads limit: %v", err)
	}

	/*cyz-> 如果可以使能AppArmor，就使能它并载入default profile。
		AppArmor(Application Armor)是Linux内核的一个安全模块，AppArmor允许系统管理员将
	每个程序与一个安全配置文件关联，从而限制程序的功能。简单的说，AppArmor是与SELinux类似
	的一个访问控制系统，通过它你可以指定程序可以读、写或运行哪些文件，是否可以打开网络端口等。
	作为对传统Unix的自主访问控制模块的补充，AppArmor提供了强制访问控制机制，它已经被整合
	到2.6版本的Linux内核中。
		Apparmor提供的访问控制是与程序绑定的.*/
	if err := ensureDefaultAppArmorProfile(); err != nil {
		logrus.Errorf(err.Error())
	}

	//cyz-> 创建容器文件夹，config.Root=="/var/lib/"
	daemonRepo := filepath.Join(config.Root, "containers")
	if err := idtools.MkdirAllAndChown(daemonRepo, 0700, rootIDs); err != nil && !os.IsExist(err) {
		return nil, err
	}

	// Create the directory where we'll store the runtime scripts (i.e. in
	// order to support runtimeArgs)
	/*cyz-> OCI runtime 此处存疑，参考以下资料？？？
		https://github.com/opencontainers/runtime-spec
		https://segmentfault.com/a/1190000009583199#articleHeader1
		http://www.infoq.com/cn/news/2017/02/Docker-Containerd-RunC
		https://www.opencontainers.org/
	*/
	daemonRuntimes := filepath.Join(config.Root, "runtimes")
	if err := system.MkdirAll(daemonRuntimes, 0700, ""); err != nil && !os.IsExist(err) {
		return nil, err
	}
	if err := d.loadRuntimes(); err != nil {
		return nil, err
	}

	if runtime.GOOS == "windows" {
		if err := system.MkdirAll(filepath.Join(config.Root, "credentialspecs"), 0, ""); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}

	// On Windows we don't support the environment variable, or a user supplied graphdriver
	// as Windows has no choice in terms of which graphdrivers to use. It's a case of
	// running Windows containers on Windows - windowsfilter, running Linux containers on Windows,
	// lcow. Unix platforms however run a single graphdriver for all containers, and it can
	// be set through an environment variable, a daemon start parameter, or chosen through
	// initialization of the layerstore through driver priority order for example.
	d.stores = make(map[string]daemonStore)
	if runtime.GOOS == "windows" {
		d.stores["windows"] = daemonStore{graphDriver: "windowsfilter"}
		if system.LCOWSupported() {
			d.stores["linux"] = daemonStore{graphDriver: "lcow"}
		}
	} else {
		driverName := os.Getenv("DOCKER_DRIVER")
		if driverName == "" {
			driverName = config.GraphDriver
		} else {
			logrus.Infof("Setting the storage driver from the $DOCKER_DRIVER environment variable (%s)", driverName)
		}
		d.stores[runtime.GOOS] = daemonStore{graphDriver: driverName} // May still be empty. Layerstore init determines instead.
	}

	d.RegistryService = registryService
	//cyz-> 将d.PluginStore注册下来，也就是保存起来
	logger.RegisterPluginGetter(d.PluginStore)

	/*cyz-> 建立一个metrics的监听套接字，并进行了合适的路由。
		监听metrics.sock套接字，并建立一个http.NewServeMux()，将"/metrics"路由到一个Handler；用goroutine开启一个新的线程接收服务
		该Handler由package prometheus建立，Package prometheus provides metrics primitives to instrument code for monitoring.*/
	metricsSockPath, err := d.listenMetricsSock()
	if err != nil {
		return nil, err
	}
	/*cyz-> 为metricsPlugin注册回调函数，回调函数用到了metricsSockPath。
		这个函数的第一个形参是plugingetter，d.PluginStore实现了plugingetter接口；
		CALLBACK，即回调函数，是一个通过函数指针调用的函数。如果你把函数的指针（地址）作为参数传递给另一个函数，当这个指针被用为调用它
		所指向的函数时，我们就说这是回调函数。回调函数不是由该函数的实现方直接调用，而是在特定的事件或条件发生时由另外的一方调用的，
		用于对该事件或条件进行响应。*/
	registerMetricsPluginCallback(d.PluginStore, metricsSockPath)

	createPluginExec := func(m *plugin.Manager) (plugin.Executor, error) {
		return pluginexec.New(getPluginExecRoot(config.Root), containerdRemote, m)
	}

	// Plugin system initialization should happen before restore. Do not change order.
	//cyz-> 新建了一个pluginManager，并将createPluginExec传入，它被用来创建一个新的pluginexec
	d.pluginManager, err = plugin.NewManager(plugin.ManagerConfig{
		Root:               filepath.Join(config.Root, "plugins"),
		ExecRoot:           getPluginExecRoot(config.Root),
		Store:              d.PluginStore,
		CreateExecutor:     createPluginExec,
		RegistryService:    registryService,
		LiveRestoreEnabled: config.LiveRestoreEnabled,
		LogPluginEvent:     d.LogPluginEvent, // todo: make private
		AuthzMiddleware:    config.AuthzMiddleware,
	})
	if err != nil {
		return nil, errors.Wrap(err, "couldn't create plugin manager")
	}

	/*cyz-> graphdriver负责容器镜像的管理。
		这个博客详细讲了layerStore，imageStore，referenceStore，distributionMetadataStore和storage driver。
	http://licyhust.com/%E5%AE%B9%E5%99%A8%E6%8A%80%E6%9C%AF/2016/09/27/docker-image-data-structure/*/
	var graphDrivers []string

	//cyz-> 这个for对于unix只有一次迭代，对于支持lcow的Windows有两次迭代
	for operatingSystem, ds := range d.stores {
		//cyz-> 创建了一个新的layer的Store实例，layer仓库（注意，这个仓库是Store而非Repo）
		ls, err := layer.NewStoreFromOptions(layer.StoreOptions{
			StorePath:                 config.Root,
			MetadataStorePathTemplate: filepath.Join(config.Root, "image", "%s", "layerdb"),
			GraphDriver:               ds.graphDriver,
			GraphDriverOptions:        config.GraphOptions,
			IDMappings:                idMappings,
			PluginGetter:              d.PluginStore,
			ExperimentalEnabled:       config.Experimental,
			OS:                        operatingSystem,
		})
		if err != nil {
			return nil, err
		}
		ds.graphDriver = ls.DriverName() // As layerstore may set the driver
		ds.layerStore = ls
		d.stores[operatingSystem] = ds
		graphDrivers = append(graphDrivers, ls.DriverName())
	}

	// Configure and validate the kernels security support
	if err := configureKernelSecuritySupport(config, graphDrivers); err != nil {
		return nil, err
	}

	logrus.Debugf("Max Concurrent Downloads: %d", *config.MaxConcurrentDownloads)
	lsMap := make(map[string]layer.Store)
	for operatingSystem, ds := range d.stores {
		lsMap[operatingSystem] = ds.layerStore
	}
	//cyz-> 创建了一个新的layer的下载管理者和上传管理者
	d.downloadManager = xfer.NewLayerDownloadManager(lsMap, *config.MaxConcurrentDownloads)
	logrus.Debugf("Max Concurrent Uploads: %d", *config.MaxConcurrentUploads)
	d.uploadManager = xfer.NewLayerUploadManager(*config.MaxConcurrentUploads)
	for operatingSystem, ds := range d.stores {
		imageRoot := filepath.Join(config.Root, "image", ds.graphDriver)
		//cyz-> 创建新的filesystem-based backend for image.Store。
		ifs, err := image.NewFSStoreBackend(filepath.Join(imageRoot, "imagedb"))
		if err != nil {
			return nil, err
		}

		//cyz-> 对于给定的ifs、ls创建新的image store
		var is image.Store
		is, err = image.NewImageStore(ifs, operatingSystem, ds.layerStore)
		if err != nil {
			return nil, err
		}
		ds.imageRoot = imageRoot
		ds.imageStore = is
		d.stores[operatingSystem] = ds
	}

	// Configure the volumes driver，此处存疑？？？
	volStore, err := d.configureVolumes(rootIDs)
	if err != nil {
		return nil, err
	}

	trustKey, err := loadOrCreateTrustKey(config.TrustKeyPath)
	if err != nil {
		return nil, err
	}

	trustDir := filepath.Join(config.Root, "trust")

	if err := system.MkdirAll(trustDir, 0700, ""); err != nil {
		return nil, err
	}

	//cyz-> 这会利用到发布-订阅模式,publish-subscribe简称pubsub
	eventsService := events.New()

	// We have a single tag/reference store for the daemon globally. However, it's
	// stored under the graphdriver. On host platforms which only support a single
	// container OS, but multiple selectable graphdrivers, this means depending on which
	// graphdriver is chosen, the global reference store is under there. For
	// platforms which support multiple container operating systems, this is slightly
	// more problematic as where does the global ref store get located? Fortunately,
	// for Windows, which is currently the only daemon supporting multiple container
	// operating systems, the list of graphdrivers available isn't user configurable.
	// For backwards compatibility, we just put it under the windowsfilter
	// directory regardless.
	refStoreLocation := filepath.Join(d.stores[runtime.GOOS].imageRoot, `repositories.json`)
	//cyz-> 这个文件保存了reference，也就是如何将repository:tag指向一个image
	rs, err := refstore.NewReferenceStore(refStoreLocation)
	if err != nil {
		return nil, fmt.Errorf("Couldn't create reference store repository: %s", err)
	}
	d.referenceStore = rs

	for platform, ds := range d.stores {
		//cyz-> creates a new filesystem-based metadata store，FS代表filesystem-based，此处存疑？？？
		dms, err := dmetadata.NewFSMetadataStore(filepath.Join(ds.imageRoot, "distribution"), platform)
		if err != nil {
			return nil, err
		}

		ds.distributionMetadataStore = dms
		d.stores[platform] = ds

		// No content-addressability migration on Windows as it never supported pre-CA
		if runtime.GOOS != "windows" {
			migrationStart := time.Now()
			if err := v1.Migrate(config.Root, ds.graphDriver, ds.layerStore, ds.imageStore, rs, dms); err != nil {
				logrus.Errorf("Graph migration failed: %q. Your old graph data was found to be too inconsistent for upgrading to content-addressable storage. Some of the old data was probably not upgraded. We recommend starting over with a clean storage directory if possible.", err)
			}
			logrus.Infof("Graph migration to content-addressability took %.2f seconds", time.Since(migrationStart).Seconds())
		}
	}

	// Discovery is only enabled when the daemon is launched with an address to advertise.  When
	// initialized, the daemon is registered and we can store the discovery backend as it's read-only
	//cyz-> --advertise-addr必须指定一个特定地址来广告它正在等待客户。所以只有指定了一个地址，Discovery才会被初始化。
	if err := d.initDiscovery(config); err != nil {
		return nil, err
	}

	sysInfo := sysinfo.New(false)
	// Check if Devices cgroup is mounted, it is hard requirement for container security,
	// on Linux.
	if runtime.GOOS == "linux" && !sysInfo.CgroupDevicesEnabled {
		return nil, errors.New("Devices cgroup isn't mounted")
	}

	d.ID = trustKey.PublicKey().KeyID()
	d.repository = daemonRepo
	//cyz-> 存储containers的store，放在memory中的。
	d.containers = container.NewMemoryStore()
	//cyz-> replica是复制品的意思，d.containersReplica、container.NewViewDB()？此处存疑？？？
	if d.containersReplica, err = container.NewViewDB(); err != nil {
		return nil, err
	}
	//cyz-> 用于记录exec config（即执行指令的详细信息）的store，exec.NewStore()？此处存疑？？？
	d.execCommands = exec.NewStore()
	d.trustKey = trustKey
	//cyz-> 此处存疑？？？
	d.idIndex = truncindex.NewTruncIndex([]string{})
	//cyz-> 此处存疑？？？
	d.statsCollector = d.newStatsCollector(1 * time.Second)
	d.defaultLogConfig = containertypes.LogConfig{
		Type:   config.LogConfig.Type,
		Config: config.LogConfig.Config,
	}
	d.EventsService = eventsService
	d.volumes = volStore
	d.root = config.Root
	d.idMappings = idMappings
	d.seccompEnabled = sysInfo.Seccomp
	d.apparmorEnabled = sysInfo.AppArmor
	d.containerdRemote = containerdRemote

	//cyz-> parent containers，alias，child containers间的映射关系。此处存疑？？？
	d.linkIndex = newLinkIndex()

	//cyz-> 每5分钟清除一次可以移除的exec configs，此处存疑？？？
	go d.execCommandGC()

	//cyz-> 此处存疑？？？
	d.containerd, err = containerdRemote.NewClient(MainNamespace, d)
	if err != nil {
		return nil, err
	}

	//cyz-> restore是恢复，尚未细看，此处存疑？？？
	if err := d.restore(); err != nil {
		return nil, err
	}
	//cyz-> 关闭这个chan，那么等待着读这个chan的就不会继续阻塞。
	close(d.startupDone)

	// FIXME: this method never returns an error
	info, _ := d.SystemInfo()

	//cyz-> 这3个engine开头的跟metrics有关，此处存疑？？？
	engineInfo.WithValues(
		dockerversion.Version,
		dockerversion.GitCommit,
		info.Architecture,
		info.Driver,
		info.KernelVersion,
		info.OperatingSystem,
		info.OSType,
		info.ID,
	).Set(1)
	engineCpus.Set(float64(info.NCPU))
	engineMemory.Set(float64(info.MemTotal))

	gd := ""
	for platform, ds := range d.stores {
		if len(gd) > 0 {
			gd += ", "
		}
		gd += ds.graphDriver
		if len(d.stores) > 1 {
			gd = fmt.Sprintf("%s (%s)", gd, platform)
		}
	}
	logrus.WithFields(logrus.Fields{
		"version":        dockerversion.Version,
		"commit":         dockerversion.GitCommit,
		"graphdriver(s)": gd,
	}).Info("Docker daemon")

	return d, nil
}

func (daemon *Daemon) waitForStartupDone() {
	<-daemon.startupDone
}

func (daemon *Daemon) shutdownContainer(c *container.Container) error {
	stopTimeout := c.StopTimeout()

	// If container failed to exit in stopTimeout seconds of SIGTERM, then using the force
	if err := daemon.containerStop(c, stopTimeout); err != nil {
		return fmt.Errorf("Failed to stop container %s with error: %v", c.ID, err)
	}

	// Wait without timeout for the container to exit.
	// Ignore the result.
	<-c.Wait(context.Background(), container.WaitConditionNotRunning)
	return nil
}

// ShutdownTimeout returns the shutdown timeout based on the max stopTimeout of the containers,
// and is limited by daemon's ShutdownTimeout.
func (daemon *Daemon) ShutdownTimeout() int {
	// By default we use daemon's ShutdownTimeout.
	shutdownTimeout := daemon.configStore.ShutdownTimeout

	graceTimeout := 5
	if daemon.containers != nil {
		for _, c := range daemon.containers.List() {
			if shutdownTimeout >= 0 {
				stopTimeout := c.StopTimeout()
				if stopTimeout < 0 {
					shutdownTimeout = -1
				} else {
					if stopTimeout+graceTimeout > shutdownTimeout {
						shutdownTimeout = stopTimeout + graceTimeout
					}
				}
			}
		}
	}
	return shutdownTimeout
}

// Shutdown stops the daemon.
func (daemon *Daemon) Shutdown() error {
	daemon.shutdown = true
	// Keep mounts and networking running on daemon shutdown if
	// we are to keep containers running and restore them.

	if daemon.configStore.LiveRestoreEnabled && daemon.containers != nil {
		// check if there are any running containers, if none we should do some cleanup
		if ls, err := daemon.Containers(&types.ContainerListOptions{}); len(ls) != 0 || err != nil {
			// metrics plugins still need some cleanup
			daemon.cleanupMetricsPlugins()
			return nil
		}
	}

	if daemon.containers != nil {
		logrus.Debugf("daemon configured with a %d seconds minimum shutdown timeout", daemon.configStore.ShutdownTimeout)
		logrus.Debugf("start clean shutdown of all containers with a %d seconds timeout...", daemon.ShutdownTimeout())
		daemon.containers.ApplyAll(func(c *container.Container) {
			if !c.IsRunning() {
				return
			}
			logrus.Debugf("stopping %s", c.ID)
			if err := daemon.shutdownContainer(c); err != nil {
				logrus.Errorf("Stop container error: %v", err)
				return
			}
			if mountid, err := daemon.stores[c.OS].layerStore.GetMountID(c.ID); err == nil {
				daemon.cleanupMountsByID(mountid)
			}
			logrus.Debugf("container stopped %s", c.ID)
		})
	}

	if daemon.volumes != nil {
		if err := daemon.volumes.Shutdown(); err != nil {
			logrus.Errorf("Error shutting down volume store: %v", err)
		}
	}

	for platform, ds := range daemon.stores {
		if ds.layerStore != nil {
			if err := ds.layerStore.Cleanup(); err != nil {
				logrus.Errorf("Error during layer Store.Cleanup(): %v %s", err, platform)
			}
		}
	}

	// If we are part of a cluster, clean up cluster's stuff
	if daemon.clusterProvider != nil {
		logrus.Debugf("start clean shutdown of cluster resources...")
		daemon.DaemonLeavesCluster()
	}

	daemon.cleanupMetricsPlugins()

	// Shutdown plugins after containers and layerstore. Don't change the order.
	daemon.pluginShutdown()

	// trigger libnetwork Stop only if it's initialized
	if daemon.netController != nil {
		daemon.netController.Stop()
	}

	if err := daemon.cleanupMounts(); err != nil {
		return err
	}

	return nil
}

// Mount sets container.BaseFS
// (is it not set coming in? why is it unset?)
func (daemon *Daemon) Mount(container *container.Container) error {
	//cyz-> 不出意外的话，对RWLayer的读写将透明反映这个union fs。此处存疑？？？
	dir, err := container.RWLayer.Mount(container.GetMountLabel())
	if err != nil {
		return err
	}
	logrus.Debugf("container mounted via layerStore: %v", dir)

	if container.BaseFS != nil && container.BaseFS.Path() != dir.Path() {
		// The mount path reported by the graph driver should always be trusted on Windows, since the
		// volume path for a given mounted layer may change over time.  This should only be an error
		// on non-Windows operating systems.
		if runtime.GOOS != "windows" {
			daemon.Unmount(container)
			return fmt.Errorf("Error: driver %s is returning inconsistent paths for container %s ('%s' then '%s')",
				daemon.GraphDriverName(container.OS), container.ID, container.BaseFS, dir)
		}
	}
	container.BaseFS = dir // TODO: combine these fields
	return nil
}

// Unmount unsets the container base filesystem
func (daemon *Daemon) Unmount(container *container.Container) error {
	if err := container.RWLayer.Unmount(); err != nil {
		logrus.Errorf("Error unmounting container %s: %s", container.ID, err)
		return err
	}

	return nil
}

// Subnets return the IPv4 and IPv6 subnets of networks that are manager by Docker.
func (daemon *Daemon) Subnets() ([]net.IPNet, []net.IPNet) {
	var v4Subnets []net.IPNet
	var v6Subnets []net.IPNet

	managedNetworks := daemon.netController.Networks()

	for _, managedNetwork := range managedNetworks {
		v4infos, v6infos := managedNetwork.Info().IpamInfo()
		for _, info := range v4infos {
			if info.IPAMData.Pool != nil {
				v4Subnets = append(v4Subnets, *info.IPAMData.Pool)
			}
		}
		for _, info := range v6infos {
			if info.IPAMData.Pool != nil {
				v6Subnets = append(v6Subnets, *info.IPAMData.Pool)
			}
		}
	}

	return v4Subnets, v6Subnets
}

// GraphDriverName returns the name of the graph driver used by the layer.Store
func (daemon *Daemon) GraphDriverName(platform string) string {
	return daemon.stores[platform].layerStore.DriverName()
}

// prepareTempDir prepares and returns the default directory to use
// for temporary files.
// If it doesn't exist, it is created. If it exists, its content is removed.
func prepareTempDir(rootDir string, rootIDs idtools.IDPair) (string, error) {
	var tmpDir string
	if tmpDir = os.Getenv("DOCKER_TMPDIR"); tmpDir == "" {
		tmpDir = filepath.Join(rootDir, "tmp")
		newName := tmpDir + "-old"
		if err := os.Rename(tmpDir, newName); err == nil {
			go func() {
				if err := os.RemoveAll(newName); err != nil {
					logrus.Warnf("failed to delete old tmp directory: %s", newName)
				}
			}()
		} else if !os.IsNotExist(err) {
			logrus.Warnf("failed to rename %s for background deletion: %s. Deleting synchronously", tmpDir, err)
			if err := os.RemoveAll(tmpDir); err != nil {
				logrus.Warnf("failed to delete old tmp directory: %s", tmpDir)
			}
		}
	}
	// We don't remove the content of tmpdir if it's not the default,
	// it may hold things that do not belong to us.
	return tmpDir, idtools.MkdirAllAndChown(tmpDir, 0700, rootIDs)
}

func (daemon *Daemon) setupInitLayer(initPath containerfs.ContainerFS) error {
	rootIDs := daemon.idMappings.RootPair()
	return initlayer.Setup(initPath, rootIDs)
}

func (daemon *Daemon) setGenericResources(conf *config.Config) error {
	genericResources, err := config.ParseGenericResources(conf.NodeGenericResources)
	if err != nil {
		return err
	}

	daemon.genericResources = genericResources

	return nil
}

func setDefaultMtu(conf *config.Config) {
	// do nothing if the config does not have the default 0 value.
	if conf.Mtu != 0 {
		return
	}
	conf.Mtu = config.DefaultNetworkMtuDefaultNetworkMtu
}

func (daemon *Daemon) configureVolumes(rootIDs idtools.IDPair) (*store.VolumeStore, error) {
	volumesDriver, err := local.New(daemon.configStore.Root, rootIDs)
	if err != nil {
		return nil, err
	}

	volumedrivers.RegisterPluginGetter(daemon.PluginStore)

	if !volumedrivers.Register(volumesDriver, volumesDriver.Name()) {
		return nil, errors.New("local volume driver could not be registered")
	}
	return store.New(daemon.configStore.Root)
}

// IsShuttingDown tells whether the daemon is shutting down or not
func (daemon *Daemon) IsShuttingDown() bool {
	return daemon.shutdown
}

// initDiscovery initializes the discovery watcher for this daemon.
func (daemon *Daemon) initDiscovery(conf *config.Config) error {
	advertise, err := config.ParseClusterAdvertiseSettings(conf.ClusterStore, conf.ClusterAdvertise)
	if err != nil {
		if err == discovery.ErrDiscoveryDisabled {
			return nil
		}
		return err
	}

	conf.ClusterAdvertise = advertise
	discoveryWatcher, err := discovery.Init(conf.ClusterStore, conf.ClusterAdvertise, conf.ClusterOpts)
	if err != nil {
		return fmt.Errorf("discovery initialization failed (%v)", err)
	}

	daemon.discoveryWatcher = discoveryWatcher
	return nil
}

func isBridgeNetworkDisabled(conf *config.Config) bool {
	return conf.BridgeConfig.Iface == config.DisableNetworkBridge
}

func (daemon *Daemon) networkOptions(dconfig *config.Config, pg plugingetter.PluginGetter, activeSandboxes map[string]interface{}) ([]nwconfig.Option, error) {
	options := []nwconfig.Option{}
	if dconfig == nil {
		return options, nil
	}

	options = append(options, nwconfig.OptionExperimental(dconfig.Experimental))
	options = append(options, nwconfig.OptionDataDir(dconfig.Root))
	options = append(options, nwconfig.OptionExecRoot(dconfig.GetExecRoot()))

	dd := runconfig.DefaultDaemonNetworkMode()
	dn := runconfig.DefaultDaemonNetworkMode().NetworkName()
	options = append(options, nwconfig.OptionDefaultDriver(string(dd)))
	options = append(options, nwconfig.OptionDefaultNetwork(dn))

	if strings.TrimSpace(dconfig.ClusterStore) != "" {
		kv := strings.Split(dconfig.ClusterStore, "://")
		if len(kv) != 2 {
			return nil, errors.New("kv store daemon config must be of the form KV-PROVIDER://KV-URL")
		}
		options = append(options, nwconfig.OptionKVProvider(kv[0]))
		options = append(options, nwconfig.OptionKVProviderURL(kv[1]))
	}
	if len(dconfig.ClusterOpts) > 0 {
		options = append(options, nwconfig.OptionKVOpts(dconfig.ClusterOpts))
	}

	if daemon.discoveryWatcher != nil {
		options = append(options, nwconfig.OptionDiscoveryWatcher(daemon.discoveryWatcher))
	}

	if dconfig.ClusterAdvertise != "" {
		options = append(options, nwconfig.OptionDiscoveryAddress(dconfig.ClusterAdvertise))
	}

	options = append(options, nwconfig.OptionLabels(dconfig.Labels))
	options = append(options, driverOptions(dconfig)...)

	if daemon.configStore != nil && daemon.configStore.LiveRestoreEnabled && len(activeSandboxes) != 0 {
		options = append(options, nwconfig.OptionActiveSandboxes(activeSandboxes))
	}

	if pg != nil {
		options = append(options, nwconfig.OptionPluginGetter(pg))
	}

	options = append(options, nwconfig.OptionNetworkControlPlaneMTU(dconfig.NetworkControlPlaneMTU))

	return options, nil
}

// GetCluster returns the cluster
func (daemon *Daemon) GetCluster() Cluster {
	return daemon.cluster
}

// SetCluster sets the cluster
func (daemon *Daemon) SetCluster(cluster Cluster) {
	daemon.cluster = cluster
}

func (daemon *Daemon) pluginShutdown() {
	manager := daemon.pluginManager
	// Check for a valid manager object. In error conditions, daemon init can fail
	// and shutdown called, before plugin manager is initialized.
	if manager != nil {
		manager.Shutdown()
	}
}

// PluginManager returns current pluginManager associated with the daemon
func (daemon *Daemon) PluginManager() *plugin.Manager { // set up before daemon to avoid this method
	return daemon.pluginManager
}

// PluginGetter returns current pluginStore associated with the daemon
func (daemon *Daemon) PluginGetter() *plugin.Store {
	return daemon.PluginStore
}

// CreateDaemonRoot creates the root for the daemon
func CreateDaemonRoot(config *config.Config) error {
	// get the canonical path to the Docker root directory
	//cyz-> 创建config.Root目录
	var realRoot string
	if _, err := os.Stat(config.Root); err != nil && os.IsNotExist(err) {
		realRoot = config.Root
	} else {
		realRoot, err = getRealPath(config.Root)
		if err != nil {
			return fmt.Errorf("Unable to get the full path to root (%s): %s", config.Root, err)
		}
	}

	/*cyz-> setupRemappedRoot创建config.Root目录，并返回一个idtools.IDMappings，它保存了uid的idMap数组和gid的idMap数组，
		一个idMap保存了{Container上的ID,Host上的ID,Size}这样一个映射关系*/
	idMappings, err := setupRemappedRoot(config)
	if err != nil {
		return err
	}
	//cyz-> setupDaemonRoot函数会为remappedRoot更改config.Root的值，config.Root变为rootDir+"rootIDs.UID.rootIDs.GID"，并创建相应目录作为root目录
	return setupDaemonRoot(config, realRoot, idMappings.RootPair())
}

// checkpointAndSave grabs a container lock to safely call container.CheckpointTo
func (daemon *Daemon) checkpointAndSave(container *container.Container) error {
	container.Lock()
	defer container.Unlock()
	if err := container.CheckpointTo(daemon.containersReplica); err != nil {
		return fmt.Errorf("Error saving container state: %v", err)
	}
	return nil
}

// because the CLI sends a -1 when it wants to unset the swappiness value
// we need to clear it on the server side
func fixMemorySwappiness(resources *containertypes.Resources) {
	if resources.MemorySwappiness != nil && *resources.MemorySwappiness == -1 {
		resources.MemorySwappiness = nil
	}
}

// GetAttachmentStore returns current attachment store associated with the daemon
func (daemon *Daemon) GetAttachmentStore() *network.AttachmentStore {
	return &daemon.attachmentStore
}
