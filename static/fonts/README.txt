Inter (https://rsms.me/inter/), version 4.1, SIL Open Font License 1.1 (Inter-LICENSE.txt).

Inter-latin.woff2 is derived from InterVariable.ttf of the official release
https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip:

  fonttools varLib.instancer InterVariable.ttf opsz=14 -o Inter-wght.ttf
  pyftsubset Inter-wght.ttf --flavor=woff2 --no-hinting \
    --unicodes="U+0000-00FF,U+0100-017F,U+0218-021B,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+2074,U+20AC,U+2122,U+2190-2193,U+2212,U+2215,U+2713,U+FEFF,U+FFFD" \
    --layout-features="kern,liga,calt,tnum,case,ss01,cv05,cv11,zero,locl,ccmp,mark,mkmk"

Latin, Latin Extended-A (Turkish included), punctuation, arrows; weight axis 100-900.
It is served from the panel itself: no request leaves the server (CSP: font-src 'self').
