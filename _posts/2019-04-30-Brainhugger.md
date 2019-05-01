---
title: RuCTF 2019 - Brainhugger
author: Pietro Ferretti
date: 30/04/2019
summary: How to completely ignore half of a challenge and still win.
categories: RuCTF2019 Attack/Defense
tags:
- ructf
- web
- crypto
- rest api
- golang
- random
- brainfuck
- padding oracle
- auth bypass
---

# Brainhugger (RuCTF 2019)

The `brainhugger` challenge at RuCTF 2019 was a simple REST API written in Go, which allowed users to register and run code written in Brainfuck.

Exploiting this challenge was crucial for our victory at RuCTF 2019, as most of the points we made were on this challenge.

The application offered four backend endpoints:

* `/register`: register a user with a password (a flag), receive a `secret` cookie used for authentication and a progressive counter (uid)
* `/login`: use the password to get your auth cookie
* `/runTask`: run brainfuck code, identified with a token (a flag)
* `/taskInfo`: get the result of the brainfuck task corresponding to a token

## Weaponized solution

### Stealing cookies

The `secret` cookie is generated directly from the password provided at registration (the password is the flag) by encrypting it with a custom CBC-mode block cipher. Since the plaintext contains the flag, we'd like to recover the cookie if possible.

```go
	plainSecret := fmt.Sprintf("%v|%v", usersCount, password)
	encryptedSecret, err := cbc.Encrypt(key, []byte(plainSecret))
```

After registration a user may login with their uid and password, and if the password matches the one saved in storage the application will set the same `secret` cookie generated during registration.

The vulnerability lies in the login logic: the application behaves peculiarly if the cookies are already set when making a request to the endpoint. If the cookies are present in the request, the application will, in order:

1. Check if the cookies are a valid `secret` and `uid` pair, i.e. they are valid credentials for an existing user;
2. If the cookies are ok, reset the `secret` cookie to the one corresponding to the uid passed in the response *body*, whichever it is.

```go
func handleLoginUser(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	var loginUser LoginUser
	err = json.Unmarshal(data, &loginUser)
	[...]
	if len(r.Cookies()) != 0 {
		ok, _, err := usersManager.ValidateCookies(r.Cookies())  // only checks if the cookies are valid
		if err != nil {
			w.WriteHeader(400)
			return
		}
		if ok {
			secret, err := usersManager.GetForCookie(loginUser.UserId)  // returns the cookie for the uid in the request body
			if err != nil {
				w.WriteHeader(400)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:  "secret",
				Value: secret,
			})
			http.SetCookie(w, &http.Cookie{
				Name:  "uid",
				Value: fmt.Sprint(loginUser.UserId),
			})
			return
		}
	}
```

By making a request to the login endpoint using the cookies of a user we registered and using a different uid in the request body, we can recover the `secret` cookie for any user we want.

The patch:

```patch
--- backend/main.go	(date 1556446794000)
+++ backend/main.go	(date 1556446794000)
@@ -168,7 +168,12 @@
 			return
 		}
 		if ok {
-			secret, err := usersManager.GetForCookie(loginUser.UserId)
+			userId, _, err := usersManager.GetFromCookie(r.Cookies())
+			if err != nil {
+				w.WriteHeader(400)
+				return
+			}
+			secret, err := usersManager.GetForCookie(userId)
 			if err != nil {
 				w.WriteHeader(400)
 				return
```

### Decrypting the cookie using predictable keys

**Note:** despite its simplicity, this vulnerability seems to be unintended by the challenge creators. The [official writeup](https://github.com/HackerDom/ructf-2019/blob/master/sploits/brainhugger/writeup.md) does not mention it, and focuses instead on the padding oracle attack.

The cookie was generated using a custom algorithm. Even without delving into the shifting, xoring and shuffling, the straightest approach is to check if the encryption key is fixed or somewhat predictable.

```go
	userId, cookie, err := usersManager.AddUser(newUser.Password, cbc.GenerateKey())
```

```go
func GenerateKey() []byte {
	key := make([]byte, KeySize)
	for i := 0; i < KeySize; i++ {
		key[i] = byte(i)
	}
	rand.Shuffle(KeySize, func(i, j int) { key[i], key[j] = key[j], key[i] })
	return key
}
```

A quick check immediately shows an issue: the `GenerateKey` function calls `rand.Shuffle`, but the seed for the PRNG is never initialized in the whole application. This means that the keys generated for every instance of the program, for every team, will be the same! We can easily list them by repeatedly calling `GenerateKey`.

To make it even easier, the only call to the `rand` package in the whole application is at registration. Since each user is identified by a progressive uid, we immediately know the key that was used at registration (provided that the application was not restarted), i.e. the key for the user with uid `100` is the result of the 100th call to the `GenerateKey` function.

This vulnerability is very easy to patch, we just need to add a call to `rand.Seed`.

```patch
--- backend/main.go	(date 1556446794000)
+++ backend/main.go	(date 1556446794000)
@@ -9,6 +9,8 @@
 	"log"
 	"net/http"
 	"strconv"
+	"math/rand"
+	"time"
 )
 
 var taskManager TasksManager
@@ -208,6 +215,7 @@
 	if err != nil {
 		panic("can not parse config: " + err.Error())
 	}
+	rand.Seed(time.Now().UTC().UnixNano())
 	if err := taskManager.Init(config.TasksDir, config.BrainHugExecutorPath, config.MaxItemsCount); err != nil {
 		panic(err)
 	}
```

### Writing the exploit

By combining the previous two vulnerabilities, we can recover flags from the application in two easy steps:

1. Get the cookie for a user registered by the checksystem;
2. Decrypt the cookie using the keys that we know will be generated by the PRNG.

Our exploit was written in Python, but since we already have an implementation of the decryption for the application's custom algorithm written in Go, we reused the application code to write a simple executable to decrypt the cookies.

You can find the Python exploit [here]({{ site.url }}/writeups_files/brainhugger/exploit.py) and the decryption program [here]({{ site.url }}/writeups_files/brainhugger/dec.go).

Since the flag was exfiltrated as ciphertext and decrypted locally using only two clean requests, the attack was likely hard to detect, and impossible to replicate. This was a big factor in the success of the exploit, which still worked on many teams even up to the end.

## Other weaknesses

There are more weaknesses and vulnerabilities that we found but we didn't think were worth the effort of weaponizing, since patching them were quite easy and the previous exploit was working really well.

### Padding oracle on the login endpoint

The flags were encrypted in CBC mode, the encryption was malleable (we could edit the plaintext by flipping bits in the ciphertext) and there was no integrity checking.
From our experience with AES, we knew that given these conditions a padding oracle attack was a good candidate for a vulnerability. 

Long story short: as long as an exposed application can tell any user whether the plaintext is padded correctly after decryption of a ciphertext given by the attacker, an attacker can use the little information that was revealed about the plaintext to recover the whole plaintext with multiple requests.

And this was the case. On the login endpoint, as long as we passed well-formed requests and cookies, the application would return 400 if any error happened during decryption, and 403 if the plaintext didn't match the password (i.e. the plaintext is padded correctly).

Exploiting this vulnerability required the same cookie stealing vulnerability as the previous exploit, so we decided it wasn't worth the effort of adapting the attack for the custom encryption algorithm (we would only need it for teams that patched the seed but not the cookie stealing vuln, unlikely).

Since we had already patched the cookie exfiltration vulnerability, patching the padding oracle was not necessary. Anyway, better be safe than sorry. We patched it by making the app return the same result in all cases of failure.

```patch
--- backend/main.go	(date 1556446794000)
+++ backend/main.go	(date 1556446794000)
@@ -197,7 +204,7 @@
 			Value: fmt.Sprint(loginUser.UserId),
 		})
 	} else {
-		w.WriteHeader(403)
+		w.WriteHeader(400)
 		return
 	}
 	w.WriteHeader(200)
```

### The brainfuck interpreter

I'll be honest: we never actually tried to understand how the interpreter worked and which bugs it had.

The fact that it was vulnerable was obvious since the executable was compiled without a stack canary:

```
all:
	if test -f bhexecutor.notc; then gcc -g -O0 -fno-stack-protector -x c bhexecutor.notc -o bhexecutor; fi
```

We opened it once to check it out, and one of the weaknesses was spelled out clear as day: if a specific parameter wasn't passed as argument, the binary restarted itself with ASLR disabled.

We added the argument to the call to the binary and we called it a day.


```patch
--- backend/bhexecutor/bhexecutor.go	(date 1556438428000)
+++ backend/bhexecutor/bhexecutor.go	(date 1556438428000)
@@ -15,7 +14,7 @@
 }
 
 func (bhExecutor *BhExecutor) RunBhCode(code string, input []byte, maxOperations uint) ([]byte, error) {
-	cmd := exec.Command(bhExecutor.BinPath, code)
+	cmd := exec.Command(bhExecutor.BinPath, "hhfg", code)
 	stdout := &bytes.Buffer{}
 	stdin := &bytes.Buffer{}
 	stderr := &bytes.Buffer{}
```

### Exfiltration from /static

We never actually patched the vulnerable brainfuck interpreter (apart from the ASLR check), so a handful of exploits passed through.

The firewall handled the reverse shells, but a specific exploit exfiltrated the flags in a different way. First it would read the flags from the files on the sistem, then save the contents to a chosen file. The magic was that the file was saved to the frontend's /static/ folder, the contents of which were by default returned for any request to the /static endpoint on the frontend.

Luckily the config file included a really convenient "StaticDir" option to change the directory used to serve static files. Since there is no way to know which directory the application was actually using, any files that would be created with the exploit would be inaccessible.

