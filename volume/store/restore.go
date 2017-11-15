package store

import (
	"sync"

	"github.com/boltdb/bolt"
	"github.com/docker/docker/volume"
	"github.com/docker/docker/volume/drivers"
	"github.com/sirupsen/logrus"
)

// restore is called when a new volume store is created.
// It's primary purpose is to ensure that all drivers' refcounts are set based
// on known volumes after a restart.
// This only attempts to track volumes that are actually stored in the on-disk db.
// It does not probe the available drivers to find anything that may have been added
// out of band.
func (s *VolumeStore) restore() {
	var ls []volumeMetadata
	//cyz-> 在bolt.DB中查询volume metadata list
	s.db.View(func(tx *bolt.Tx) error {
		ls = listMeta(tx)
		return nil
	})

	chRemove := make(chan *volumeMetadata, len(ls))
	var wg sync.WaitGroup
	//cyz-> 对list每个metadata（即一个volume），创建一个go程创建它的driver并将volume保存，将需要移除的vol放入chRemove
	for _, meta := range ls {
		wg.Add(1)
		// this is potentially a very slow operation, so do it in a goroutine
		go func(meta volumeMetadata) {
			defer wg.Done()

			var v volume.Volume
			var err error
			if meta.Driver != "" {
				v, err = lookupVolume(meta.Driver, meta.Name)
				if err != nil && err != errNoSuchVolume {
					logrus.WithError(err).WithField("driver", meta.Driver).WithField("volume", meta.Name).Warn("Error restoring volume")
					return
				}
				if v == nil {
					// doesn't exist in the driver, remove it from the db
					chRemove <- &meta
					return
				}
			} else {
				v, err = s.getVolume(meta.Name)
				if err != nil {
					if err == errNoSuchVolume {
						chRemove <- &meta
					}
					return
				}

				meta.Driver = v.DriverName()
				if err := s.setMeta(v.Name(), meta); err != nil {
					logrus.WithError(err).WithField("driver", meta.Driver).WithField("volume", v.Name()).Warn("Error updating volume metadata on restore")
				}
			}

			// increment driver refcount
			//cyz-> local属于长存的，不会加refcount；plugin driver也只会加1引用，同样的访问会直接返回，因为在存储中找到了。
			volumedrivers.CreateDriver(meta.Driver)

			// cache the volume
			s.globalLock.Lock()
			s.options[v.Name()] = meta.Options
			s.labels[v.Name()] = meta.Labels
			s.names[v.Name()] = v
			s.globalLock.Unlock()
		}(meta)
	}

	//cyz-> 等待所有go程完成然后关闭chRemove，在bolt.DB中移除这些vol
	wg.Wait()
	close(chRemove)
	s.db.Update(func(tx *bolt.Tx) error {
		for meta := range chRemove {
			if err := removeMeta(tx, meta.Name); err != nil {
				logrus.WithField("volume", meta.Name).Warnf("Error removing stale entry from volume db: %v", err)
			}
		}
		return nil
	})
}
