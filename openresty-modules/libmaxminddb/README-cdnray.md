# For CDNRay

CDNRay 上不再使用 yum 的 `libmaxminddb-devel` package，而是自行編譯此自定義版本，command 可參考

```bash
git clone --recursive ssh://git@admin.skycloud.tw:1022/skycloud-rd/libmaxminddb.git
cd libmaxminddb/
./bootstrap
./configure
make
make check
sudo make install
sudo ldconfig
```

> NOTE: 如果沒有 `automake`、`autoconf` 或 `libtool`，請先安裝
