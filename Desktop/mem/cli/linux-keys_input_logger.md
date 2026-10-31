# view access to keyboards
getent group input # read
getent group uinput # write

sudo lsof /dev/input/event*
sudo lsof /dev/uinput

