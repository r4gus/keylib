int uhid_open();
void uhid_close(int fd);
int uhid_read_packet(int fd, char* out);
int uhid_write_packet(int fd, char* in, size_t len);
