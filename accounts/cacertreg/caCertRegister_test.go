package cacertreg

import (
	"fmt"
	"testing"
)

func TestCAVerify(t *testing.T) {
	//two params is true,and there is only one file.
	err := CAVerify("110", "C:\\Users\\DELL\\Desktop\\1540526567(1).jpg")
	if err != nil {
		t.Errorf("error:%v", err)
	} else {
		fmt.Println("##########two params is true,and there is only one file, so we got register success!")
	}

}
func TestCAVerifyFilepathErrorSeparator(t *testing.T) {
	//filepath is not exist
	err := CAVerify("110", "C:\\Users\\DELL\\Desktop\\1540526567(1).jpg|C:\\Users\\DELL\\Desktop\\1540457451(1).jpg")
	if err != nil {
		t.Errorf("##############false separator symble test, error:  %v", err)
	} else {
		fmt.Println("register success!")
	}
}
func TestCAVerifyIDIsEmpty(t *testing.T) {
	//id is empty but file path is true.
	err := CAVerify("", "C:\\Users\\DELL\\Desktop\\1540526567(1).jpg")
	if err != nil {
		t.Errorf("################userid empty test, error:  %v", err)
	}
}
func TestCAVerifyTwoFile(t *testing.T) {
	//two params is true,more file.
	err := CAVerify("110", "C:\\Users\\DELL\\Desktop\\1540526567(1).jpg;C:\\Users\\DELL\\Desktop\\1540457451(1).jpg")
	if err != nil {
		t.Errorf("error:%v", err)
	}
}
func TestCAVerifyParamsIsEmpty(t *testing.T) {
	//file not found
	err := CAVerify("", "")
	if err != nil {
		t.Errorf("#############two empty params test, error:  %v", err)
	}
}

func TestCAVerifyPhotoIsEmpty(t *testing.T) {
	err := CAVerify("123123", "")
	if err != nil {
		t.Errorf("#############photo path is empty test, error:  %v", err)
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
		t.Errorf("################idkey is empty test, error:  %v", err)
	}
}
