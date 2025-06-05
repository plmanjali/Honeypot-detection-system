{pkgs}: {
  deps = [
    pkgs.sqlite
    pkgs.glibcLocales
    pkgs.wireshark
    pkgs.tcpdump
    pkgs.sox
    pkgs.imagemagickBig
    pkgs.postgresql
    pkgs.openssl
  ];
}
