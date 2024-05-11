package message

import (
	"fmt"
	"os/exec"
)

const SET_KEY_FIRST = "set key first."
const SHOULBE_16_24_32 = "key length should be 16 or 24 or 32 byte"

func get_randombytes(length int) (random []byte, err error) {
	/* refer http://hensa40.cutegirl.jp/archives/1034 */
	bs := fmt.Sprintf("bs=%d", length)
	//	random, err = exec.Command("dd", "if=/dev/urandom", "bs=12", "count=1").Output()
	random, err = exec.Command("dd", "if=/dev/urandom", bs, "count=1").Output()
	return
}
