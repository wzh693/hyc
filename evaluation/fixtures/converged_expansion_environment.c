int bounded_read(const unsigned char *data, unsigned long size, unsigned long index) {
    if (!data || index >= size) return -1;
    return data[index];
}
