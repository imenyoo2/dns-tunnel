
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

ssize_t write_tun(int tun_fd, char *buf, size_t len)
{
  int bytes_written = write(tun_fd, buf, len);
  if (bytes_written != len) {
    fprintf(stderr, "write_tun: expected %lu got %d\n", len, bytes_written);
  }
  return bytes_written;
}

ssize_t read_tun(int tun_fd, char *buf, size_t len)
{
	int bytes;
	memset(buf, 0, 4);

	bytes = read(tun_fd, buf + 4, len - 4);
	if (bytes < 0) {
		return bytes;
	} else {
		return bytes + 4;
	}
}

int set_if_ip(const char *dev, const char *ip_addr)
{
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;

    if (inet_pton(AF_INET, ip_addr, &addr->sin_addr) != 1) {
        perror("inet_pton");
        close(sockfd);
        return -1;
    }

    // Set the IP address
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFADDR)");
        close(sockfd);
        return -1;
    }

    // Bring the interface up
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCGIFFLAGS)");
        close(sockfd);
        return -1;
    }

    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCSIFFLAGS)");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
       return -1;

    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TUN;
    if( *dev )
       strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
       close(fd);
       return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

int main(void) {
  char tun_name[IFNAMSIZ] = "tun38";
  int fd = tun_alloc(tun_name);

  printf("fd = %d\n", fd);

  /*
  if (set_if_ip(tun_name, "10.0.0.1") < 0) {
    fprintf(stderr, "Failed to set IP\n");
    return 1;
  }
  */

  char buffer[1024];
  int bytes_read;
  while (1) {
    bytes_read = read_tun(fd, buffer, 1024);
    printf("bytes_read = %d\n", bytes_read);
    for (ssize_t i = 0; i < bytes_read; i++) {
      if (i % 20 == 0) {
        printf("\n");
      }
      printf("%02x ", (unsigned char)buffer[i]);
    }
    printf("\n");
    if (bytes_read != 56) {
      break;
    }
  }

  char tmp[5];
  while (1) {
    write(1, ">", 1);
    read(0, tmp, 1);
    write_tun(fd, buffer + 4, bytes_read - 4);
  }

  return 0;
}
