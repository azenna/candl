#include <unistd.h>

int main() {

	setregid(getegid(), getegid());
	execve("/bin/sh", 0, 0);

	return 0;
}
