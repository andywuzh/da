package main

import (
	"bufio"
	"crypto/sha256"
	"da/crypter"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

const (
	version = "0.1.0"
)

var (
	// GitHash 版本hash, 编译时设置
	GitHash = "None"
	// BuildTS 构建时间, 编译时设置
	BuildTS = "None"

	showVsn = flag.Bool("v", false, "show version")

	infile  = flag.String("infile", "", "input file, default is STDIN")
	outfile = flag.String("outfile", "", "output file, default is STDOUT")
	appid   = flag.String("appid", "", "APPID")
	secret  = flag.String("secret", "", "APP SECRET")
)

func usage() {
	fmt.Fprintf(os.Stderr, `
Developer Assistant

Version: %s 
BuildTS: %s
GitHash: %s

`, version, BuildTS, GitHash)

	fmt.Fprintf(os.Stderr, "Flags:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Parse()
	flag.Usage = usage

	if *showVsn {
		usage()
		return
	}

	var err error
	var rs []string

	if *infile != "" {
		rfp, err := os.Open(*infile)
		if err != nil {
			log.Fatal(err)
		}
		defer rfp.Close()

		err = readline(rfp, func(s string) {
			es, _ := encrypt(s, *secret)
			rs = append(rs, es)
		})
	} else {
		err = readline(os.Stdin, func(s string) {
			es, _ := encrypt(s, *secret)
			rs = append(rs, es)
		})
	}
	if err != nil {
		log.Fatal(err)
	}

	if *outfile != "" {
		wfp, err := os.Create(*outfile)
		if err != nil {
			log.Fatal(err)
		}
		defer wfp.Close()

		err = writelines(wfp, rs)
	} else {
		err = writelines(os.Stdout, rs)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func encrypt(content, secret string) (string, error) {
	key := sha256.Sum256([]byte(secret))

	s, err := crypter.EncryptECB(content, string(key[:]))
	if err != nil {
		fmt.Print(err)
		return "", err
	}

	return s, nil
}

func decrypt(data, secret string) (string, error) {
	key := sha256.Sum256([]byte(secret))
	s, err := crypter.DecryptECB(data, string(key[:]))
	if err != nil {
		fmt.Print(err)
		return "", err
	}

	return s, nil
}

func readline(r io.Reader, handler func(string)) error {
	rb := bufio.NewReader(r)
	for {
		line, err := rb.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				if str := strings.TrimSpace(line); str != "" {
					handler(str)
				}

				return nil
			}
			return err
		}

		handler(strings.TrimSpace(line))
	}
}

func writelines(w io.Writer, contents []string) error {
	wb := bufio.NewWriter(w)
	for _, content := range contents {
		_, err := wb.WriteString(fmt.Sprintln(content))
		if err != nil {
			return err
		}
	}
	wb.Flush()

	return nil
}
