#include "types.h"
#include "user.h"

int main(int argc, char *argv[]){
    int pid = fork();
    if(pid==0){
        printf(1, "Child process: %d\n", getpid());
        exit();
    } else {
        wait();
        printf(1, "Parent process: %d\n", getpid());
    }
    hello();
    exit();
}