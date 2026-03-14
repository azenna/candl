#include <unistd.h>

int main() {
	setregid(getgid(), getgid());
	execve("/bin/sh", 0, 0);
}
