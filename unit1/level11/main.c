#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    time_t currentTime;

    currentTime = time(NULL);


    srand((unsigned int)currentTime);

    int randomNumber = rand(); 
			       //
    printf("%d\n", randomNumber);
	
    return 0;
}
