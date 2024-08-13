#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashMap.h"

// Funzione per creare una nuova hash table
HashTable *hashCreate(void) {
    HashTable *x = calloc(1, sizeof(HashTable));
    for (int i = 0; i < SIZE; i++) {
        x->items[i] = NULL;
    }
    return x;
}

// Funzione per inserire un elemento nella hash table
void *hashInsert(HashTable *table, unsigned int key, void *value) {
    Item *item = calloc(1, sizeof(Item));
    item->key = key;
    item->value = value;  // Non usiamo strdup, copiamo solo il puntatore
    item->next = NULL;

    int index = key % SIZE;
    if (table->items[index] != NULL) {
        Item *current = table->items[index];
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = item;
    } else {
        table->items[index] = item;
    }
    return NULL;
}

// Funzione per cercare un valore nella hash table dato un key
void *hashSearch(HashTable *table, unsigned int key) {
    int index = key % SIZE;
    Item *current = table->items[index];

    while (current != NULL) {
        if (current->key == key) {
            return current->value;
        }
        current = current->next;
    }
    return NULL;
}

// Funzione per eliminare un elemento dalla hash table
void hashDelete(HashTable *table, unsigned int key) {
    int index = key % SIZE;
    Item *current = table->items[index];
    Item *previous = NULL;

    while (current != NULL && current->key != key) {
        previous = current;
        current = current->next;
    }

    if (current == NULL) {
        // Chiave non trovata
        return;
    }

    if (previous == NULL) {
        // L'elemento da eliminare è il primo nella lista
        table->items[index] = current->next;
    } else {
        previous->next = current->next;
    }

    // Non usiamo più free(current->value); perché non sappiamo come è stata allocata
    free(current);
}

// Funzione per liberare la memoria occupata dalla hash table
void hashFree(HashTable *table) {
    for (int i = 0; i < SIZE; i++) {
        Item *current = table->items[i];
        while (current != NULL) {
            Item *temp = current;
            current = current->next;
            // Non usiamo più free(temp->value); perché non sappiamo come è stata allocata
            free(temp);
        }
    }
    free(table);
}
