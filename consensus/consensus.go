/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

package consensus

import (
	"OntologyWithPOC/account"
	"OntologyWithPOC/common/config"
	"OntologyWithPOC/common/log"
	"OntologyWithPOC/consensus/dbft"
	"OntologyWithPOC/consensus/poc"
	"OntologyWithPOC/consensus/poc/config"
	"OntologyWithPOC/consensus/solo"
	"OntologyWithPOC/consensus/vbft"
	"context"
	"github.com/fsnotify/fsnotify"
	"github.com/ontio/ontology-eventbus/actor"
	"github.com/spf13/viper"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type ConsensusService interface {
	Start() error
	Halt() error
	GetPID() *actor.PID
}

const (
	CONSENSUS_DBFT = "dbft"
	CONSENSUS_SOLO = "solo"
	CONSENSUS_VBFT = "vbft"
	CONSENSUS_POC  = "poc"
)

var quitWg sync.WaitGroup

//调用os.MkdirAll递归创建文件夹
func createFile(filePath string) error {
	if !isExist(filePath) {
		err := os.MkdirAll(filePath, os.ModePerm)
		return err
	}
	return nil
}

// 判断所给路径文件/文件夹是否存在(返回true是存在)
func isExist(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func GetAllFileSize(pathname string) uint64 {
	rd, err := ioutil.ReadDir(pathname)
	if err != nil {
		panic(err)
	}
	var sumSize uint64
	for _, fi := range rd {
		if fi.IsDir() {
			log.Info("[%s]\n", pathname+"\\"+fi.Name())
		} else {
			sumSize += uint64(fi.Size())
		}
	}
	return sumSize
}

type DiskStatus struct {
	All  uint64
	Used uint64
	Free uint64
}

const (
	B  = 1
	KB = 1024 * B
	MB = 1024 * KB
	GB = 1024 * MB
)

func DiskUsage(path string) (disk DiskStatus) {
	fs := syscall.Statfs_t{}
	err := syscall.Statfs(path, &fs)
	if err != nil {
		return
	}
	disk.All = fs.Blocks * uint64(fs.Bsize)
	disk.Free = fs.Bfree * uint64(fs.Bsize)
	disk.Used = disk.All - disk.Free

	//kernel32, err := syscall.LoadLibrary("Kernel32.dll")
	//if err != nil {
	//	log.Error(err)
	//}
	//defer syscall.FreeLibrary(kernel32)
	//GetDiskFreeSpaceEx, err := syscall.GetProcAddress(syscall.Handle(kernel32), "GetDiskFreeSpaceExW")
	//
	//if err != nil {
	//	log.Error(err)
	//}
	//
	//lpFreeBytesAvailable := int64(0)
	//lpTotalNumberOfBytes := int64(0)
	//lpTotalNumberOfFreeBytes := int64(0)
	//_, _, err = syscall.Syscall6(uintptr(GetDiskFreeSpaceEx), 4,
	//	uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("C:"))),
	//	uintptr(unsafe.Pointer(&lpFreeBytesAvailable)),
	//	uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
	//	uintptr(unsafe.Pointer(&lpTotalNumberOfFreeBytes)), 0, 0)
	//
	//log.Infof("Available  %dmb", lpFreeBytesAvailable/1024/1024.0)
	//log.Infof("Total      %dmb", lpTotalNumberOfBytes/1024/1024.0)
	//log.Infof("Free       %dmb", lpTotalNumberOfFreeBytes/1024/1024.0)

	return
}

type configViper struct {
	v *viper.Viper
}

//监听配置文件的修改和变动
func WatchConfig(c *configViper, account *account.Account) error {
	if err := LoadConfigFromProperties(c, account); err != nil {
		return err
	}
	ctx, _ := context.WithCancel(context.Background())

	//监听回调函数
	watch := func(e fsnotify.Event) {
		log.Infof("=======================================dig_status: %s, wallet_url: %s, mining_use_space: %s",
			c.v.Get("dig_status"),
			c.v.Get("wallet_url"),
			c.v.Get("mining_use_space"),
		)
		space, _ := strconv.ParseUint(c.v.Get("mining_use_space").(string), 10, 64)
		disk := DiskUsage(".")
		if disk.Free/MB > 2*space {
			switch c.v.Get("mining_use_space").(type) {
			case string:
				if config.DefConfig.Genesis.POC.PocSpace < space {
					filespace := GetAllFileSize(config.DefConfig.Genesis.POC.NonceDir)
					dfspace := space * 1024 * 1024
					if filespace < dfspace && (dfspace-filespace)/262144 != 0 {
						for i := uint64(0); i < (dfspace-filespace)/262144; i++ {
							nonceNr := rand.New(rand.NewSource(time.Now().UnixNano())).Uint64()
							pubkey := pocconfig.PubkeyID(account.PubKey())
							poc.Callshabal("genNonce256", []byte(strconv.FormatUint(nonceNr, 10)), []byte(pubkey),
								[]byte(strconv.Itoa(0)), []byte(""), []byte(config.DefConfig.Genesis.POC.NonceDir))
						}
					} else {
						log.Info("There is enough nonce file, the space is more than the default config!!!")
					}
				} else {
					dfspace := space * 1024 * 1024
					rd, err := ioutil.ReadDir(config.DefConfig.Genesis.POC.NonceDir)
					if err != nil {
						panic(err)
					}
					for _, fi := range rd {
						if fi.IsDir() {
							continue
						} else {
							//err = os.Remove(config.DefConfig.Genesis.POC.NonceDir + "/" + fi.Name())
							err = os.Truncate(config.DefConfig.Genesis.POC.NonceDir+"/"+fi.Name(), 0)
							if err != nil {
								log.Error(err)
								continue
							}
							filespace := GetAllFileSize(config.DefConfig.Genesis.POC.NonceDir)
							if filespace <= dfspace {
								break
							}
						}
					}
				}
			}
		} else {
			log.Warn("There is not enough disk space for poc space!!! The disk space must bigger than the config poc space.")
		}
		//cancel()
	}
	c.v.OnConfigChange(watch)

	c.v.WatchConfig()
	<-ctx.Done()
	return nil
}

func LoadConfigFromProperties(c *configViper, account *account.Account) error {
	c.v = viper.New()

	//设置配置文件的名字
	c.v.SetConfigName("mining_config")

	//添加配置文件所在的路径
	c.v.AddConfigPath("./")

	//设置配置文件类型
	c.v.SetConfigType("properties")

	if err := c.v.ReadInConfig(); err != nil {
		log.Error(err)
		log.Error("The configuration file does not exist, so the front-end configuration information cannot be read")
	}

	disk := DiskUsage(".")
	if disk.Free/MB < config.DefConfig.Genesis.POC.PocSpace {
		config.DefConfig.Genesis.POC.PocSpace = disk.Free / (MB * 3)
	}

	err := createFile(config.DefConfig.Genesis.POC.NonceDir)
	if err != nil {
		panic(err)
	}
	filespace := GetAllFileSize(config.DefConfig.Genesis.POC.NonceDir)
	pocspace := config.DefConfig.Genesis.POC.PocSpace
	dfspace := pocspace * 1024 * 1024
	if filespace < dfspace && (dfspace-filespace)/262144 != 0 {
		for i := uint64(0); i < (dfspace-filespace)/262144; i++ {
			nonceNr := rand.New(rand.NewSource(time.Now().UnixNano())).Uint64()
			pubkey := pocconfig.PubkeyID(account.PubKey())
			poc.Callshabal("genNonce256", []byte(strconv.FormatUint(nonceNr, 10)), []byte(pubkey),
				[]byte(strconv.Itoa(0)), []byte(""), []byte(config.DefConfig.Genesis.POC.NonceDir))
		}
	} else {
		log.Info("There is enough nonce file, the space is more than the default config!!!")
	}

	return nil
}

func NewConsensusService(consensusType string, account *account.Account, txpool *actor.PID, ledger *actor.PID, p2p *actor.PID) (ConsensusService, error) {
	if consensusType == "" {
		consensusType = CONSENSUS_DBFT
	}
	var consensus ConsensusService
	var err error
	switch consensusType {
	case CONSENSUS_DBFT:
		consensus, err = dbft.NewDbftService(account, txpool, p2p)
	case CONSENSUS_SOLO:
		consensus, err = solo.NewSoloService(account, txpool)
	case CONSENSUS_VBFT:
		consensus, err = vbft.NewVbftServer(account, txpool, p2p)
	case CONSENSUS_POC:
		go func() {
			c := configViper{}
			err = WatchConfig(&c, account)
			if err != nil {
				log.Error(err)
			}
		}()
		consensus, err = poc.NewPocServer(account, txpool, p2p)
	}
	log.Infof("ConsensusType:%s", consensusType)
	return consensus, err
}
