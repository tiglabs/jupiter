

#include <stdio.h>
#include <stdlib.h>

#include "conhash.h"

struct node_s g_nodes[64];
int main()
{
    int i;
    const struct node_s *node;
    char str[128];
    long hashes[512];

    /* init conhash instance */
    struct conhash_s *conhash = conhash_init(NULL);
    if(conhash)
    {
        /* set nodes */
        conhash_set_node(&g_nodes[0], "titanic", 32);
        conhash_set_node(&g_nodes[1], "terminator2018", 24);
        conhash_set_node(&g_nodes[2], "Xenomorph", 25);
        conhash_set_node(&g_nodes[3], "True Lies", 10);
        conhash_set_node(&g_nodes[4], "avantar", 48);

        /* add nodes */
        conhash_add_node(conhash, &g_nodes[0]);
        conhash_add_node(conhash, &g_nodes[1]);
        conhash_add_node(conhash, &g_nodes[2]);
        conhash_add_node(conhash, &g_nodes[3]);
        conhash_add_node(conhash, &g_nodes[4]);

        printf("virtual nodes number %d\n", conhash_get_vnodes_num(conhash));
        printf("the hashing results--------------------------------------:\n");

        /* try object */
        for(i = 0; i < 20; i++)
        {
            sprintf(str, "James.km%03d", i);
            node = conhash_lookup(conhash, str, NULL);
            if(node) printf("[%16s] is in node: [%16s]\n", str, node->iden);
        }
        conhash_get_vnodes(conhash, hashes, sizeof(hashes)/sizeof(hashes[0]));
        conhash_del_node(conhash, &g_nodes[2]);
        printf("remove node[%s], virtual nodes number %d\n", g_nodes[2].iden, conhash_get_vnodes_num(conhash));
        printf("the hashing results--------------------------------------:\n");
        for(i = 0; i < 20; i++)
        {
            sprintf(str, "James.km%03d", i);
            node = conhash_lookup(conhash, str, NULL);
            if(node) printf("[%16s] is in node: [%16s]\n", str, node->iden);
        }
    }
    conhash_fini(conhash);
    return 0;
}
