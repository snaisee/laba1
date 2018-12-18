package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/fullsailor/pkcs7"
)

func main() {
	var err error
	var mode, hash, cert, key, source string
	flag.StringVar(&mode, "mode", ".", "Enter z to Zip, x to Extract, i for Info")
	flag.StringVar(&source, "path", ".", "Enter path to files")
	flag.StringVar(&hash, "hash", "", "Enter SHA-1 certificate")
	flag.StringVar(&cert, "cert", "my.crt", "Enter path to certificate (~/my.crt)")
	flag.StringVar(&key, "key", "my.key", "Enter path to file with key ( ~/my.key)")

	flag.Parse()

	switch mode {
	case "z":
	
	func ifZ(source, key, cert string) (err error) {
	fmt.Println("Zip")
	bufbyte, Jmeta, mN, err := ZipFiles(source)
	if err != nil {
		return
	}

	fi, err := os.Stat(mN)
	if err != nil {
		return
	}
	size := uint32(fi.Size())

	sizeByte := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeByte, size)

	var a string
	a, err = filepath.Abs(source)
	if err != nil {
		return
	}
	archName := filepath.Base(a) + ".szp"

	rLen := len(sizeByte) + len(Jmeta) + len(bufbyte)
	bodySZP := make([]byte, 0, rLen)
	bodySZP = append(bodySZP, sizeByte...)
	bodySZP = append(bodySZP, Jmeta...)
	bodySZP = append(bodySZP, bufbyte...)

	pkey, err := KeyLoaiding(key)
	if err != nil {
		return
	}
	pcert, _, err := CertLoaiding(cert)
	if err != nil {
		return
	}
	finalData, err := signing(bodySZP, pkey, pcert)
	if err != nil {
		return
	}

	if err = ioutil.WriteFile(archName, finalData, os.ModePerm); err != nil {
		return
	}
	return
}

	case "x":
 func ifX(source, hash string) error {
	fmt.Println("Extract")
	szip, err := Extract(source, hash)
	if err != nil {
		return err
	}
	
	metaLength := binary.LittleEndian.Uint32(szip[:4])
	j := szip[4 : metaLength+4]

	var jm []MetaData
	er := json.Unmarshal(j, &jm)
	if er != nil {
		return er
	}

	bzip := szip[metaLength+4:]
	r, err := zip.NewReader(bytes.NewReader(bzip), int64(len(bzip)))
	if err != nil {
		return err
	}
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		fpath := f.Name


		}
		
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, f.Mode())
			continue
		}
		var fdir string
		if lastIndex := strings.LastIndex(fpath, "/"); lastIndex > -1 {
			fdir = fpath[:lastIndex]
		}

		err = os.MkdirAll(fdir, f.Mode())
		if err != nil {
			return err
		}
		f, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(f, rc)
		if err != nil {
			return err
		}

	}

	return err
	case "i":
	func ifI(source, hash string) error {
	fmt.Println("Info")
	szip, err := Extract(source, hash)
	if err != nil {
		return err
	}
	
	metaLength := binary.LittleEndian.Uint32(szip[:4])
	j := szip[4 : metaLength+4]
	fmt.Println(string(j))

	return err
}

	}
	if err != nil {
		log.Fatal(err)
	}

}

func KeyLoaiding(key string) (pkey crypto.PrivateKey, err error) {

	pmKey, err := ioutil.ReadFile(key)
	if err != nil {
		return
	}

	block, _ := pem.Decode(pmKey)
	if block == nil {
		err = fmt.Errorf("Error")
		return
	}

	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return
	}

	pkey = parseResult.(*rsa.PrivateKey)
	return
}

func CertLoaiding(cert string) (pcert *x509.Certificate, CtrB []byte, err error) {
	
	CtrB, err = ioutil.ReadFile(cert)
	if err != nil {
		return
	}
	
	block, _ := pem.Decode(CtrB)
	if block == nil {
		err = fmt.Errorf("Error")
		return
	}
	
	pcert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}


	return pcert, CtrB, err
}

func signing(bufbyte []byte, pkey crypto.PrivateKey, pcert *x509.Certificate) (sData []byte, err error) {
	
	Data, err := pkcs7.NewData(bufbyte)
	if err != nil {
		return
	}
	
	if err = Data.AddSigner(pcert, pkey, pkcs7.SignerInfoConfig{}); err != nil {
		return
	}
	
	return Data.Finish()
}


type MetaData struct {
	Name     string
	FullPath string
	Size     int64
	ModTime  string
	Hash     string
}

func ZipFiles(path string, zipWriter *zip.Writer, dirName string) error {

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	
	for _, file := range files {
		if file.IsDir() {
			_, err := zipWriter.Create(filepath.Join(dirName, file.Name()) + "/")
			if err != nil {
				return err
			}
			err = ZipFiles(filepath.Join(path, file.Name()), zipWriter, filepath.Join(dirName, file.Name()))
			if err != nil {
				return err
			}
		} else {
			L := new(sFile)
			data, err := os.Open(filepath.Join(path, file.Name()))
			defer data.Close()
			if err != nil {
				return err
			}

			info, err := data.Stat()
			if err != nil {
				return err
			}

			header, err := zip.FileInfoHeader(info)

			if err != nil {
				return err
			}

			header.Name = filepath.Join(dirName, file.Name())

			header.Method = zip.Deflate

			zwriter, err := zipWriter.CreateHeader(header)
			if err != nil {
				return err
			}
			if _, err = io.Copy(zwriter, data); err != nil {
				return err

			}
			L.Name = filepath.Join(path, file.Name())
			L.Size = file.Size()
			L.CSize = int64(header.CompressedSize64)
			L.Modify = header.Modified
			h := sha1.New()
			d, err := ioutil.ReadFile(L.Name)
			if err != nil {
				return err
			}
			h.Write(d)

			L.Hash = base64.URLEncoding.EncodeToString(h.Sum(nil))
			List = append(List, *L)

		}
	}
	return nil
}
func hashFile(f *zip.File) (string, error) {
	var err error
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	hs := sha1.New()
	if _, err := io.Copy(hs, rc); err != nil {
		return "", err
	}
	hsb := hash.Sum(nil)[:20]
	hsf := hex.EncodeToString(hsb)
	return hsf, err
}

func Extract(source, hash string) (szip []byte, err error) {

	szip, err = ioutil.ReadFile(source)
	if err != nil {
		return
	}
	
	parseSign, err := pkcs7.Parse(szip)
	if err != nil {
		return
	}
	
	err = parseSign.Verify()
	if err != nil {
		return
	}

	szip = parseSign.Content
	if hash == "" {
		return
	}

	return szip, hashVerify(hash, parseSign)
}

func hashVerify(hash string, parseSign *pkcs7.PKCS7) error {
	x509Cert := parseSign.GetOnlySigner()
	if x509Cert == nil {
		return fmt.Errorf("Error ")
	}

	hCert := sha1.New()
	var hString string
	hInBytes := hCert.Sum(x509Cert.Raw)[:20]
	hString = hex.EncodeToString(hInBytes)

	if hash != hString {
		return fmt.Errorf("Error ")
	}

	fmt.Println("SHA-1 cert check confirmed")
	return nil
}

}
