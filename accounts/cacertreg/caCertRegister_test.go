package cacertreg

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

//Generate a random string of the specified length
func GetRandomString(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

func TestCAVerify(t *testing.T) {
	//two params is true,and there is only one file.
	userID := GetRandomString(32)
	fmt.Println("userID: ", userID)
	err := CAVerify(userID, "./testdata/img1.jpg")
	if err != nil {
		t.Errorf("error:%v", err)
	} else {
		fmt.Println("two params is true,and there is only one file, so we got register success!")
	}

}
func TestCAVerifyFilepathErrorSeparator(t *testing.T) {
	userID := GetRandomString(32)
	fmt.Println("userID: ", userID)
	//filepath is not correct
	err := CAVerify(userID, "./testdata/img1.jpg|./testdata/img2.jpg")
	if err != nil {
		t.Errorf("false separator symble test, error:  %v", err)
	} else {
		fmt.Println("register success!")
	}
}
func TestCAVerifyIDIsEmpty(t *testing.T) {
	//id is empty but file path is true.
	err := CAVerify("", "./testdata/img1.jpg")
	if err != nil {
		t.Errorf("userid empty test, error:  %v", err)
	}
}
func TestCAVerifyTwoFile(t *testing.T) {
	userID := GetRandomString(32)
	fmt.Println("userID: ", userID)
	//two params is true,more file.
	err := CAVerify(userID, "./testdata/img1.jpg;./testdata/img2.jpg")
	if err != nil {
		t.Errorf("error:%v", err)
	}
}
func TestCAVerifyParamsIsEmpty(t *testing.T) {
	//file not found
	err := CAVerify("", "")
	if err != nil {
		t.Errorf("two empty params test, error:  %v", err)
	}
}

func TestCAVerifyPhotoIsEmpty(t *testing.T) {
	userID := GetRandomString(32)
	fmt.Println("userID: ", userID)
	err := CAVerify(userID, "")
	if err != nil {
		t.Errorf("photo path is empty test, error:  %v", err)
	}
}

func TestVerifyQuery(t *testing.T) {

	//idkey is exist
	err := VerifyQuery("71910e1159398046c281c7bba825ab5d")
	if err != nil {
		t.Errorf("error:  %v", err)
	}
}
func TestVerifyQueryIDKeyIsNotExist(t *testing.T) {
	//idkey is not exist
	err := VerifyQuery("71910e1159398046c281c7bba825dedd")
	if err != nil {
		t.Errorf("error:  %v", err)
	}
}
func TestVerifyQueryIDIsEmpty(t *testing.T) {
	//test emtpy idkey
	err := VerifyQuery("")
	if err != nil {
		t.Errorf("idkey is empty test, error:  %v", err)
	}
}
