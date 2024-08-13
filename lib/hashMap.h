#ifndef HASHMAP_H
#define HASHMAP_H

#define SIZE 512

typedef struct Item {
    unsigned int key;
    void *value;
    struct Item *next;
} Item;

typedef struct HashTable {
    Item *items[SIZE];
} HashTable;

HashTable *hashCreate(void);
void *hashInsert(HashTable *table, unsigned int key, void *value);
void *hashSearch(HashTable *table, unsigned key);
void hashDelete(HashTable *table, unsigned int key);
void hashFree(HashTable *table);

#endif
