[![Build Status](https://travis-ci.org/spoofzu/DeepVioletTools.svg?branch=master)](https://travis-ci.org/spoofzu/DeepVioletTools)
[![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/europe/2016.svg)](http://www.blackhat.com/eu-16/arsenal.html#milton-smith)
[![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/usa/2018.svg)](https://www.blackhat.com/us-18/arsenal/schedule/index.html#deepviolet-ssltls-scanning-api-38-tools-10724)

## OWASP DeepVioletTools

[OWASP Project Page](https://www.owasp.org/index.php/OWASP_DeepViolet_TLS/SSL_Scanner) | 
[WIKI](https://github.com/spoofzu/DeepVioletTools/wiki) | 
[DV API JavaDocs](https://github.com/spoofzu/DeepViolet/wiki/Hardhats)

DeepViolet(DV) is a TLS/SSL scanning API written in Java. To keep DV easy to use, identify bugs, reference implementations have been developed in this project that consume the [DV API](https://github.com/spoofzu/DeepViolet/). If you want to see what DV can do, use it from the command line in your scripts or use the graphical tool from the comfort of your desktop. Both tools can be used to scan HTTPS web servers to check server certificate trust chains, revocation status, check certificates for pending expiration, weak signing algorithms and much more.  Original blog article post describing this project, http://www.securitycurmudgeon.com/2014/07/ssltls-introspection.html

## Screenshots

Run DV from the UI from the desktop.

```
java -jar dvUI.jar
```
![deepviolet-git](https://cloud.githubusercontent.com/assets/8450615/14919921/e04f22c4-0ddf-11e6-9d16-2b15e1a57c37.jpg)

Run DV from the shell on the command line.

```
java -jar dvCMD.jar -serverurl https://www.github.com/ -s thrcisn
```

![dvcmd-snapshot](https://cloud.githubusercontent.com/assets/8450615/15344407/8209d2ba-1c5b-11e6-9321-3397ba35359d.png)

## Acknowledgements
This tool impliments ideas, code, and takes inspriation from other projects and leaders like: Qualys SSL Labs and Ivan Ristić, OpenSSL, and Oracle's Java Security Team.  Many thanks negotiating TLS/SSL handshakes and ciphersuite handling adapted from code examples by Thomas Pornin.

Looking for more information?  See the [project wiki](https://github.com/spoofzu/DeepVioletTools/wiki) or the [API wiki](https://github.com/spoofzu/DeepViolet/wiki)

<i>This project leverages the works of other open source community projects and is provided for educational purposes.  Use at your own risk.  See [LICENSE](https://github.com/spoofzu/DeepViolet/blob/master/LICENSE) for further information.</i>
