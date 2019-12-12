package poc

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"
)

func calDeadline(pathname string) int {
	nonceNr := rand.New(rand.NewSource(time.Now().UnixNano())).Uint64()
	pubkey := "035110e9"
	Callshabal("genNonce256", []byte(strconv.FormatUint(nonceNr, 10)), []byte(pubkey), []byte(strconv.Itoa(0)), []byte(""), []byte(pathname))
	presig := "1496cf14"
	pregen := "ab5c35fd"
	blheight := rand.New(rand.NewSource(time.Now().UnixNano())).Int()
	rd, err := ioutil.ReadDir(pathname)
	if err != nil {
		fmt.Println(err)
		return -1
	}
	for _, fi := range rd {
		if fi.IsDir() {
			fmt.Println(pathname+"\\"+fi.Name())
		} else if fi.Name() == ".DS_Store" {
			continue
		} else {
			Callshabal("genHash_Target256", []byte(presig), []byte(pregen), []byte(strconv.Itoa(blheight)), []byte(pathname), []byte(fi.Name()))
			baseTarget := "5c35fd15"
			fileObj,err := os.Open(pathname + "/target" + strconv.Itoa(blheight))
			if err != nil {
				fmt.Println(err)
				continue
			}
			target,err := ioutil.ReadAll(fileObj)
			if err != nil {
				fmt.Println(err)
			}
			target0Int, err := bytesToIntU(target[0:1])
			if err != nil {
				fmt.Println(err)
			}
			baseTargetInt, err := bytesToIntU([]byte(baseTarget))
			if err != nil {
				fmt.Println(err)
			}
			if target0Int != 0 {
				deadline := baseTargetInt / target0Int
				fileObj.Close()
				return deadline
			}
			fileObj.Close()
			return -1
		}
	}
	return -1
}

func Test_shabal256(t *testing.T) {
	var deadlines []int
	for sum := 0; sum < 30; sum++ {
		deadline := calDeadline("/Users/zhourunze/Cache/test")
		deadlines = append(deadlines, deadline)
	}
	// 排序
	sort.Sort(sort.IntSlice(deadlines))
	fmt.Println(deadlines)
}