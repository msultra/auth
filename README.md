<h1 align="center">
    <br>
    <img style="border-radius: 50%;" src="https://github.com/msultra.png" width="200px" alt="msultra/auth">
    <br>
    Auth - Part of MsUltra
</h1>

<h4 align="center">Library that implements authentication methods for Windows. SPNEGO, with embedded providers.</h4>

<p align="center">
    <img src="https://img.shields.io/github/go-mod/go-version/msultra/auth">
    <img src="https://github.com/msultra/auth/actions/workflows/test.yml/badge.svg">
    <a href="https://goreportcard.com/report/github.com/msultra/auth"><img src="https://goreportcard.com/badge/msultra/auth"></a>
    <a href="https://pkg.go.dev/github.com/msultra/auth"><img src="https://pkg.go.dev/badge/github.com/msultra/auth.svg"></a>
</p>

---

Auth is a library that implements authentication methods for Windows. SPNEGO, with embedded providers. For more information about SPNEGO, see the [RFC 4178](https://www.rfc-editor.org/rfc/rfc4178.html). Note that Microsoft has extended the SPNEGO protocol with a useless extension called NegTokenInit2. Have fun!