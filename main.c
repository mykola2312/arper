#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t mac_t[6];

void parse_mac(const char* str, mac_t mac)
{
    char* s = strdup(str);
    char* octet = strtok(s, ":");
    int i = 0;
    
    while (octet != NULL && i < 6)
    {
        mac[i++] = strtol(octet, NULL, 16);

        octet = strtok(NULL, ":");
    }

    free(s);
}

int main()
{
    mac_t t;
    parse_mac("11:22:33:44:55:66", t);
    printf("%x\n", t[5]);

    return 0;
}