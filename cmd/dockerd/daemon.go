package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/distribution/uuid"
	"github.com/docker/docker/api"
	apiserver "github.com/docker/docker/api/server"
	buildbackend "github.com/docker/docker/api/server/backend/build"
	"github.com/docker/docker/api/server/middleware"
	"github.com/docker/docker/api/server/router"
	"github.com/docker/docker/api/server/router/build"
	checkpointrouter "github.com/docker/docker/api/server/router/checkpoint"
	"github.com/docker/docker/api/server/router/container"
	distributionrouter "github.com/docker/docker/api/server/router/distribution"
	"github.com/docker/docker/api/server/router/image"
	"github.com/docker/docker/api/server/router/network"
	pluginrouter "github.com/docker/docker/api/server/router/plugin"
	sessionrouter "github.com/docker/docker/api/server/router/session"
	swarmrouter "github.com/docker/docker/api/server/router/swarm"
	systemrouter "github.com/docker/docker/api/server/router/system"
	"github.com/docker/docker/api/server/router/volume"
	"github.com/docker/docker/builder/dockerfile"
	"github.com/docker/docker/builder/fscache"
	"github.com/docker/docker/cli/debug"
	"github.com/docker/docker/daemon"
	"github.com/docker/docker/daemon/cluster"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/daemon/listeners"
	"github.com/docker/docker/daemon/logger"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/libcontainerd"
	dopts "github.com/docker/docker/opts"
	"github.com/docker/docker/pkg/authorization"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/pkg/pidfile"
	"github.com/docker/docker/pkg/plugingetter"
	"github.com/docker/docker/pkg/signal"
	"github.com/docker/docker/pkg/system"
	"github.com/docker/docker/plugin"
	"github.com/docker/docker/registry"
	"github.com/docker/docker/runconfig"
	"github.com/docker/go-connections/tlsconfig"
	swarmapi "github.com/docker/swarmkit/api"
	"github.com/moby/buildkit/session"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

// DaemonCli represents the daemon CLI.
type DaemonCli struct {
	*config.Config
	configFile *string
	flags      *pflag.FlagSet

	api             *apiserver.Server
	d               *daemon.Daemon
	authzMiddleware *authorization.Middleware // authzMiddleware enables to dynamically reload the authorization plugins
}

// NewDaemonCli returns a daemon CLI
func NewDaemonCli() *DaemonCli {
	return &DaemonCli{}
}

func (cli *DaemonCli) start(opts *daemonOptions) (err error) {
	stopc := make(chan bool)
	defer close(stopc)

	// warn from uuid package when running the daemon
	uuid.Loggerf = logrus.Warnf

	opts.SetDefaultOptions(opts.flags)

	//cyz-> 从options生成config，此处还顺带将configFile和config合并
	if cli.Config, err = loadDaemonCliConfig(opts); err != nil {
		return err
	}
	cli.configFile = &opts.configFile
	cli.flags = opts.flags

	if cli.Config.Debug {
		debug.Enable()
	}

	if cli.Config.Experimental {
		logrus.Warn("Running experimental build")
	}

	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: jsonmessage.RFC3339NanoFixed,
		DisableColors:   cli.Config.RawLogs,
		FullTimestamp:   true,
	})

	//cyz-> InitLCOW does nothing since LCOW is a windows only feature. 
	system.InitLCOW(cli.Config.Experimental)

	//cyz-> 设置默认权限掩码0022，与chmod的码相反
	if err := setDefaultUmask(); err != nil {
		return fmt.Errorf("Failed to set umask: %v", err)
	}

	//cyz-> 设置log的config，如果有的话
	if len(cli.LogConfig.Config) > 0 {
		if err := logger.ValidateLogOpts(cli.LogConfig.Type, cli.LogConfig.Config); err != nil {
			return fmt.Errorf("Failed to set log opts: %v", err)
		}
	}

	// Create the daemon root before we create ANY other files (PID, or migrate keys)
	// to ensure the appropriate ACL(Access Control List) is set (particularly relevant on Windows)
	//cyz-> 创建config.Root目录，设置remap，如果有remappedRoot的话，config.Root变为rootDir+"rootIDs.UID.rootIDs.GID"，并创建相应目录作为root目录
	if err := daemon.CreateDaemonRoot(cli.Config); err != nil {
		return err
	}

	/*cyz-> 允许通过-p指定pidfile以避免重复，或者指定""就不用检查啦！
		pidfile一般用于daemon程序，主要作用是保证在系统中只存在该daemon的一个进程，同时也便于系统统一管理这些daemon程序。
		一般的daemon程序，不管最终接口是直接用C实现还是用SHELL包装，都需要提供start，stop及restart功能。
	
		start过程需要处理的问题：
			1. 确保系统中没有该daemon的进程。如果有，则不能启动程序。
			2. 在daemon化之后，创建pidfile，写入pid。
			3. 注册atexit()，确保在程序退出时清除pidfile文件。
		stop过程做的处理：
			1. 如果pidfile不存在，无需其它动作。
			2. 如果pidfile存在，kill原有进程，并确认进程不存在。在旧进程异常退出时，比如直接用_exit(2)退出程序时，可能pidfile不会被删除，所以在kill进程之后还要确认pidfile文件已被删除。
		restart动作：
			1. stop
			2. start*/
	if cli.Pidfile != "" {
		pf, err := pidfile.New(cli.Pidfile)
		if err != nil {
			return fmt.Errorf("Error starting daemon: %v", err)
		}
		defer func() {
			if err := pf.Remove(); err != nil {
				logrus.Error(err)
			}
		}()
	}

	// TODO: extract to newApiServerConfig()
	//cyz-> 设置下面的apiserver的Config
	serverConfig := &apiserver.Config{
		Logging:     true,
		SocketGroup: cli.Config.SocketGroup,
		Version:     dockerversion.Version,
		CorsHeaders: cli.Config.CorsHeaders,
	}

	//cyz-> 如果定义了TLS的话
	if cli.Config.TLS {
		tlsOptions := tlsconfig.Options{
			CAFile:             cli.Config.CommonTLSOptions.CAFile,
			CertFile:           cli.Config.CommonTLSOptions.CertFile,
			KeyFile:            cli.Config.CommonTLSOptions.KeyFile,
			ExclusiveRootPools: true,
		}

		if cli.Config.TLSVerify {
			// server requires and verifies client's certificate
			//cyz-> 这里使用了第三方库 tls
			tlsOptions.ClientAuth = tls.RequireAndVerifyClientCert
		}
		tlsConfig, err := tlsconfig.Server(tlsOptions)
		if err != nil {
			return err
		}
		serverConfig.TLSConfig = tlsConfig
	}

	if len(cli.Config.Hosts) == 0 {
		cli.Config.Hosts = make([]string, 1)
	}

	/*cyz-> 利用api/server的New方法根据serverConfig返回一个新的apiserver.Server；
		这个很重要，它包含了*Config，[]*HTTPServer，[]router.Router，*routerSwapper和[]middleware.Middleware
		apiserver负责监听并将请求通过mux.Router进行路由转发，此处存疑？？？还不详细------------------------------*/
	cli.api = apiserver.New(serverConfig)

	var hosts []string

	//cyz-> 这个循环为Config里所有的Hosts创建监听字并存入cli.api中
	for i := 0; i < len(cli.Config.Hosts); i++ {
		var err error
		//cyz-> 此处的ParseHost根据是否设置了TLS和Host参数来返回一个Host，如果Host为空，会返回一个默认的Host（unix）；
		//cyz-> 如果Host不为空但没有指定协议，默认使用tcp协议。支持（tcp、unix、named_pipe、fd）
		if cli.Config.Hosts[i], err = dopts.ParseHost(cli.Config.TLS, cli.Config.Hosts[i]); err != nil {
			return fmt.Errorf("error parsing -H %s : %v", cli.Config.Hosts[i], err)
		}

		protoAddr := cli.Config.Hosts[i]
		protoAddrParts := strings.SplitN(protoAddr, "://", 2)
		if len(protoAddrParts) != 2 {
			return fmt.Errorf("bad format %s, expected PROTO://ADDR", protoAddr)
		}

		proto := protoAddrParts[0]
		addr := protoAddrParts[1]

		// It's a bad idea to bind to TCP without tlsverify.
		if proto == "tcp" && (serverConfig.TLSConfig == nil || serverConfig.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert) {
			logrus.Warn("[!] DON'T BIND ON ANY IP ADDRESS WITHOUT setting --tlsverify IF YOU DON'T KNOW WHAT YOU'RE DOING [!]")
		}
		//cyz-> 根据不同的协议类型初始化Listener。
		ls, err := listeners.Init(proto, addr, serverConfig.SocketGroup, serverConfig.TLSConfig)
		if err != nil {
			return err
		}
		ls = wrapListeners(proto, ls)
		// If we're binding to a TCP port, make sure that a container doesn't try to use it.
		//cyz-> 通过portallocator分配port给daemon，portallocator.Get()利用单例模式返回一个全局唯一的portallocator
		if proto == "tcp" {
			if err := allocateDaemonPort(addr); err != nil {
				return err
			}
		}
		logrus.Debugf("Listener created for HTTP on %s (%s)", proto, addr)
		hosts = append(hosts, protoAddrParts[1])
		//cyz-> 根据Listeners新建HTTPServer结构，并放到cli.api.servers
		cli.api.Accept(addr, ls...)
	}

	//cyz-> 先根据ServiceOptions进行配置allow-nondistributable-artifacts，registry-mirrors，insecure-registries
	//cyz-> 返回一个DefaultService， is a registry service. It tracks configuration data such as a list of mirrors.
	registryService, err := registry.NewService(cli.Config.ServiceOptions)
	if err != nil {
		return err
	}

	//cyz-> 什么是libcontainerd.Remote？此处存疑？？？
	rOpts, err := cli.getRemoteOptions()
	if err != nil {
		return fmt.Errorf("Failed to generate containerd options: %s", err)
	}
	containerdRemote, err := libcontainerd.New(filepath.Join(cli.Config.Root, "containerd"), filepath.Join(cli.Config.ExecRoot, "containerd"), rOpts...)
	if err != nil {
		return err
	}
	//cyz-> 这里处理INT, TERM, QUIT, SIGPIPE信号。里面参数func()是cleanup函数，它从stopc读一个信号，阻塞住，只有close了才能返回了。
	signal.Trap(func() {
		cli.stop()
		<-stopc // wait for daemonCli.start() to return
	}, logrus.StandardLogger())

	// Notify that the API is active, but before daemon is set up.
	//cyz-> 空函数
	preNotifySystem()

	pluginStore := plugin.NewStore()

	//cyz-> 什么是Middlewares？此处存疑？？？
	if err := cli.initMiddlewares(cli.api, serverConfig, pluginStore); err != nil {
		logrus.Fatalf("Error creating middlewares: %v", err)
	}

	//cyz-> 利用前面的配置Config, registryService, containerdRemote, pluginStore建立一个新的daemon
	d, err := daemon.NewDaemon(cli.Config, registryService, containerdRemote, pluginStore)
	if err != nil {
		return fmt.Errorf("Error starting daemon: %v", err)
	}

	//cyz-> StoreHosts stores the addresses the daemon is listening on
	d.StoreHosts(hosts)

	// validate after NewDaemon has restored enabled plugins. Don't change order.
	//cyz-> 在daemon创建之后查看the plugins requested with the --authorization-plugin flag是否有效。
	if err := validateAuthzPlugins(cli.Config.AuthorizationPlugins, pluginStore); err != nil {
		return fmt.Errorf("Error validating authorization plugin: %v", err)
	}

	// TODO: move into startMetricsServer()
	if cli.Config.MetricsAddress != "" {
		if !d.HasExperimental() {
			return fmt.Errorf("metrics-addr is only supported when experimental is enabled")
		}
		//cyz-> metrics只支持experimental；启动metrics服务，这个函数监听“tcp”，listenMetricsSock函数监听“unix”
		if err := startMetricsServer(cli.Config.MetricsAddress); err != nil {
			return err
		}
	}

	// TODO: createAndStartCluster()
	name, _ := os.Hostname()

	// Use a buffered channel to pass changes from store watch API to daemon
	// A buffer allows store watch API and daemon processing to not wait for each other
	//cyz-> swarmapi.WatchMessage发送给daemon
	watchStream := make(chan *swarmapi.WatchMessage, 32)

	//cyz-> 配置一个cluster
	c, err := cluster.New(cluster.Config{
		Root:                   cli.Config.Root,
		Name:                   name,
		Backend:                d,
		PluginBackend:          d.PluginManager(),
		NetworkSubnetsProvider: d,
		DefaultAdvertiseAddr:   cli.Config.SwarmDefaultAdvertiseAddr,
		RuntimeRoot:            cli.getSwarmRunRoot(),
		WatchStream:            watchStream,
	})
	if err != nil {
		logrus.Fatalf("Error creating cluster component: %v", err)
	}

	//cyz-> Setcluster将d.cluster=c
	d.SetCluster(c)
	err = c.Start()
	if err != nil {
		logrus.Fatalf("Error starting cluster component: %v", err)
	}

	// Restart all autostart containers which has a swarm endpoint
	// and is not yet running now that we have successfully
	// initialized the cluster.
	d.RestartSwarmContainers()

	logrus.Info("Daemon has completed initialization")

	cli.d = d

	routerOptions, err := newRouterOptions(cli.Config, d)
	if err != nil {
		return err
	}
	routerOptions.api = cli.api
	routerOptions.cluster = c

	initRouter(routerOptions)

	// process cluster change notifications
	//cyz-> 此处存疑？？？
	watchCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.ProcessClusterNotifications(watchCtx, watchStream)

	cli.setupConfigReloadTrap()

	// The serve API routine never exits unless an error occurs
	// We need to start it as a goroutine and wait on it so
	// daemon doesn't exit
	serveAPIWait := make(chan error)
	go cli.api.Wait(serveAPIWait)

	// after the daemon is done setting up we can notify systemd api
	//cyz-> 此处存疑？？？
	notifySystem()

	// Daemon is fully initialized and handling API traffic
	// Wait for serve API to complete
	//cyz-> serveAPIWait会一直阻塞，直到有某个server发生了非ErrServerClosed错误，或者所有server都返回ErrServerClosed错误
	errAPI := <-serveAPIWait

	//cyz-> 此处存疑？？？
	c.Cleanup()
	shutdownDaemon(d)
	containerdRemote.Cleanup()
	if errAPI != nil {
		return fmt.Errorf("Shutting down due to ServeAPI error: %v", errAPI)
	}

	return nil
}

type routerOptions struct {
	sessionManager *session.Manager
	buildBackend   *buildbackend.Backend
	buildCache     *fscache.FSCache
	daemon         *daemon.Daemon
	api            *apiserver.Server
	cluster        *cluster.Cluster
}

func newRouterOptions(config *config.Config, daemon *daemon.Daemon) (routerOptions, error) {
	opts := routerOptions{}
	sm, err := session.NewManager()
	if err != nil {
		return opts, errors.Wrap(err, "failed to create sessionmanager")
	}

	builderStateDir := filepath.Join(config.Root, "builder")

	buildCache, err := fscache.NewFSCache(fscache.Opt{
		Backend: fscache.NewNaiveCacheBackend(builderStateDir),
		Root:    builderStateDir,
		GCPolicy: fscache.GCPolicy{ // TODO: expose this in config
			MaxSize:         1024 * 1024 * 512,  // 512MB
			MaxKeepDuration: 7 * 24 * time.Hour, // 1 week
		},
	})
	if err != nil {
		return opts, errors.Wrap(err, "failed to create fscache")
	}

	manager, err := dockerfile.NewBuildManager(daemon, sm, buildCache, daemon.IDMappings())
	if err != nil {
		return opts, err
	}

	bb, err := buildbackend.NewBackend(daemon, manager, buildCache)
	if err != nil {
		return opts, errors.Wrap(err, "failed to create buildmanager")
	}

	return routerOptions{
		sessionManager: sm,
		buildBackend:   bb,
		buildCache:     buildCache,
		daemon:         daemon,
	}, nil
}

func (cli *DaemonCli) reloadConfig() {
	reload := func(config *config.Config) {

		// Revalidate and reload the authorization plugins
		if err := validateAuthzPlugins(config.AuthorizationPlugins, cli.d.PluginStore); err != nil {
			logrus.Fatalf("Error validating authorization plugin: %v", err)
			return
		}
		cli.authzMiddleware.SetPlugins(config.AuthorizationPlugins)

		if err := cli.d.Reload(config); err != nil {
			logrus.Errorf("Error reconfiguring the daemon: %v", err)
			return
		}

		if config.IsValueSet("debug") {
			debugEnabled := debug.IsEnabled()
			switch {
			case debugEnabled && !config.Debug: // disable debug
				debug.Disable()
			case config.Debug && !debugEnabled: // enable debug
				debug.Enable()
			}

		}
	}

	if err := config.Reload(*cli.configFile, cli.flags, reload); err != nil {
		logrus.Error(err)
	}
}

func (cli *DaemonCli) stop() {
	cli.api.Close()
}

// shutdownDaemon just wraps daemon.Shutdown() to handle a timeout in case
// d.Shutdown() is waiting too long to kill container or worst it's
// blocked there
func shutdownDaemon(d *daemon.Daemon) {
	shutdownTimeout := d.ShutdownTimeout()
	ch := make(chan struct{})
	go func() {
		d.Shutdown()
		close(ch)
	}()
	if shutdownTimeout < 0 {
		<-ch
		logrus.Debug("Clean shutdown succeeded")
		return
	}
	select {
	case <-ch:
		logrus.Debug("Clean shutdown succeeded")
	case <-time.After(time.Duration(shutdownTimeout) * time.Second):
		logrus.Error("Force shutdown daemon")
	}
}

func loadDaemonCliConfig(opts *daemonOptions) (*config.Config, error) {
	conf := opts.daemonConfig
	flags := opts.flags
	conf.Debug = opts.Debug
	conf.Hosts = opts.Hosts
	conf.LogLevel = opts.LogLevel
	conf.TLS = opts.TLS
	conf.TLSVerify = opts.TLSVerify
	conf.CommonTLSOptions = config.CommonTLSOptions{}

	if opts.TLSOptions != nil {
		conf.CommonTLSOptions.CAFile = opts.TLSOptions.CAFile
		conf.CommonTLSOptions.CertFile = opts.TLSOptions.CertFile
		conf.CommonTLSOptions.KeyFile = opts.TLSOptions.KeyFile
	}

	if conf.TrustKeyPath == "" {
		conf.TrustKeyPath = filepath.Join(
			getDaemonConfDir(conf.Root),
			defaultTrustKeyFile)
	}

	if flags.Changed("graph") && flags.Changed("data-root") {
		return nil, fmt.Errorf(`cannot specify both "--graph" and "--data-root" option`)
	}

	//cyz-> 这个地方将config-file合并到config中了。
	if opts.configFile != "" {
		c, err := config.MergeDaemonConfigurations(conf, flags, opts.configFile)
		if err != nil {
			if flags.Changed("config-file") || !os.IsNotExist(err) {
				return nil, fmt.Errorf("unable to configure the Docker daemon with file %s: %v", opts.configFile, err)
			}
		}
		// the merged configuration can be nil if the config file didn't exist.
		// leave the current configuration as it is if when that happens.
		if c != nil {
			conf = c
		}
	}

	if err := config.Validate(conf); err != nil {
		return nil, err
	}

	if !conf.V2Only {
		logrus.Warnf(`The "disable-legacy-registry" option is deprecated and wil be removed in Docker v17.12. Interacting with legacy (v1) registries will no longer be supported in Docker v17.12"`)
	}

	if flags.Changed("graph") {
		logrus.Warnf(`The "-g / --graph" flag is deprecated. Please use "--data-root" instead`)
	}

	// Labels of the docker engine used to allow multiple values associated with the same key.
	// This is deprecated in 1.13, and, be removed after 3 release cycles.
	// The following will check the conflict of labels, and report a warning for deprecation.
	//
	// TODO: After 3 release cycles (17.12) an error will be returned, and labels will be
	// sanitized to consolidate duplicate key-value pairs (config.Labels = newLabels):
	//
	// newLabels, err := daemon.GetConflictFreeLabels(config.Labels)
	// if err != nil {
	//	return nil, err
	// }
	// config.Labels = newLabels
	//
	if _, err := config.GetConflictFreeLabels(conf.Labels); err != nil {
		logrus.Warnf("Engine labels with duplicate keys and conflicting values have been deprecated: %s", err)
	}

	// Regardless of whether the user sets it to true or false, if they
	// specify TLSVerify at all then we need to turn on TLS
	if conf.IsValueSet(FlagTLSVerify) {
		conf.TLS = true
	}

	// ensure that the log level is the one set after merging configurations
	setLogLevel(conf.LogLevel)

	return conf, nil
}

//cyz-> 初始化routers，
func initRouter(opts routerOptions) {
	decoder := runconfig.ContainerDecoder{}

	//cyz-> 这个函数特别重要，从这里可以看到整个docker工作的流程。-------------------------------------------------------
	routers := []router.Router{
		// we need to add the checkpoint router before the container router or the DELETE gets masked
		checkpointrouter.NewRouter(opts.daemon, decoder),
		container.NewRouter(opts.daemon, decoder),
		image.NewRouter(opts.daemon, decoder),
		systemrouter.NewRouter(opts.daemon, opts.cluster, opts.buildCache),
		volume.NewRouter(opts.daemon),
		build.NewRouter(opts.buildBackend, opts.daemon),
		sessionrouter.NewRouter(opts.sessionManager),
		swarmrouter.NewRouter(opts.cluster),
		pluginrouter.NewRouter(opts.daemon.PluginManager()),
		distributionrouter.NewRouter(opts.daemon),
	}

	if opts.daemon.NetworkControllerEnabled() {
		routers = append(routers, network.NewRouter(opts.daemon, opts.cluster))
	}

	if opts.daemon.HasExperimental() {
		for _, r := range routers {
			for _, route := range r.Routes() {
				if experimental, ok := route.(router.ExperimentalRoute); ok {
					experimental.Enable()
				}
			}
		}
	}

	//cyz-> 这个方法创建了mux.Router，mux就是多路复用器，将这些router给整合到一个去。
	opts.api.InitRouter(routers...)
}

// TODO: remove this from cli and return the authzMiddleware
func (cli *DaemonCli) initMiddlewares(s *apiserver.Server, cfg *apiserver.Config, pluginStore plugingetter.PluginGetter) error {
	v := cfg.Version

	exp := middleware.NewExperimentalMiddleware(cli.Config.Experimental)
	s.UseMiddleware(exp)

	vm := middleware.NewVersionMiddleware(v, api.DefaultVersion, api.MinVersion)
	s.UseMiddleware(vm)

	if cfg.CorsHeaders != "" {
		c := middleware.NewCORSMiddleware(cfg.CorsHeaders)
		s.UseMiddleware(c)
	}

	cli.authzMiddleware = authorization.NewMiddleware(cli.Config.AuthorizationPlugins, pluginStore)
	cli.Config.AuthzMiddleware = cli.authzMiddleware
	s.UseMiddleware(cli.authzMiddleware)
	return nil
}

func (cli *DaemonCli) getRemoteOptions() ([]libcontainerd.RemoteOption, error) {
	opts := []libcontainerd.RemoteOption{}

	pOpts, err := cli.getPlatformRemoteOptions()
	if err != nil {
		return nil, err
	}
	opts = append(opts, pOpts...)
	return opts, nil
}

// validates that the plugins requested with the --authorization-plugin flag are valid AuthzDriver
// plugins present on the host and available to the daemon
func validateAuthzPlugins(requestedPlugins []string, pg plugingetter.PluginGetter) error {
	for _, reqPlugin := range requestedPlugins {
		if _, err := pg.Get(reqPlugin, authorization.AuthZApiImplements, plugingetter.Lookup); err != nil {
			return err
		}
	}
	return nil
}
