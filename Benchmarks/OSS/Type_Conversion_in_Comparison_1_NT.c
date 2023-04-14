/*

Commit Number: f9bfec180f91671d8ba72a01cab1781c1f5e9999
URL: https://github.com/squireblackdens/daapd/commit/f9bfec180f91671d8ba72a01cab1781c1f5e9999
Project Name: daapd
License: GPL-2.0
termination: FALSE
*/
#include <stdlib.h>
int main()
{
    unsigned short int s, seqnum, len;
    seqnum = __VERIFIER_nondet_ushort();
    len = __VERIFIER_nondet_ushort();;
    for( s = seqnum ; s < seqnum + len; s++ )
    {
    	if (seqnum + len > 65535) abort();

    }
    return 0;
}
