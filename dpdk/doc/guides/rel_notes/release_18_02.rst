DPDK Release 18.02
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      make doc-guides-html

      xdg-open build/doc/html/guides/rel_notes/release_18_02.html


New Features
------------

.. This section should contain new features added in this release. Sample
   format:

   * **Add a title in the past tense with a full stop.**

     Add a short 1-2 sentence description in the past tense. The description
     should be enough to allow someone scanning the release notes to
     understand the new feature.

     If the feature adds a lot of sub-features you can use a bullet list like
     this:

     * Added feature foo to do something.
     * Enhanced feature bar to do something else.

     Refer to the previous release notes for examples.

     This section is a comment. do not overwrite or remove it.
     Also, make sure to start the actual text at the margin.
     =========================================================

* **Added function to allow releasing internal EAL resources on exit.**

  During ``rte_eal_init()`` EAL allocates memory from hugepages to enable its
  core libraries to perform their tasks. The ``rte_eal_cleanup()`` function
  releases these resources, ensuring that no hugepage memory is leaked. It is
  expected that all DPDK applications call ``rte_eal_cleanup()`` before
  exiting. Not calling this function could result in leaking hugepages, leading
  to failure during initialization of secondary processes.

* **Added igb, ixgbe and i40e ethernet driver to support RSS with flow API.**

  Added support for igb, ixgbe and i40e NICs with existing RSS configuration
  using the ``rte_flow`` API.

  Also enabled queue region configuration using the ``rte_flow`` API for i40e.

* **Updated i40e driver to support PPPoE/PPPoL2TP.**

  Updated i40e PMD to support PPPoE/PPPoL2TP with PPPoE/PPPoL2TP supporting
  profiles which can be programmed by dynamic device personalization (DDP)
  process.

* **Added MAC loopback support for i40e.**

  Added MAC loopback support for i40e in order to support test tasks requested
  by users. It will setup ``Tx -> Rx`` loopback link according to the device
  configuration.

* **Added support of run time determination of number of queues per i40e VF.**

  The number of queue per VF is determined by its host PF. If the PCI address
  of an i40e PF is ``aaaa:bb.cc``, the number of queues per VF can be
  configured with EAL parameter like ``-w aaaa:bb.cc,queue-num-per-vf=n``. The
  value n can be 1, 2, 4, 8 or 16. If no such parameter is configured, the
  number of queues per VF is 4 by default.

* **Updated mlx5 driver.**

  Updated the mlx5 driver including the following changes:

  * Enabled compilation as a plugin, thus removed the mandatory dependency with rdma-core.
    With the special compilation, the rdma-core libraries will be loaded only in case
    Mellanox device is being used. For binaries creation the PMD can be enabled, still not
    requiring from every end user to install rdma-core.
  * Improved multi-segment packet performance.
  * Changed driver name to use the PCI address to be compatible with OVS-DPDK APIs.
  * Extended statistics for physical port packet/byte counters.
  * Converted to the new offloads API.
  * Supported device removal check operation.

* **Updated mlx4 driver.**

  Updated the mlx4 driver including the following changes:

  * Enabled compilation as a plugin, thus removed the mandatory dependency with rdma-core.
    With the special compilation, the rdma-core libraries will be loaded only in case
    Mellanox device is being used. For binaries creation the PMD can be enabled, still not
    requiring from every end user to install rdma-core.
  * Improved data path performance.
  * Converted to the new offloads API.
  * Supported device removal check operation.

* **Added NVGRE and UDP tunnels support in Solarflare network PMD.**

  Added support for NVGRE, VXLAN and GENEVE tunnels.

  * Added support for UDP tunnel ports configuration.
  * Added tunneled packets classification.
  * Added inner checksum offload.

* **Added AVF (Adaptive Virtual Function) net PMD.**

  Added a new net PMD called AVF (Adaptive Virtual Function), which supports
  Intel® Ethernet Adaptive Virtual Function (AVF) with features such as:

  * Basic Rx/Tx burst
  * SSE vectorized Rx/Tx burst
  * Promiscuous mode
  * MAC/VLAN offload
  * Checksum offload
  * TSO offload
  * Jumbo frame and MTU setting
  * RSS configuration
  * stats
  * Rx/Tx descriptor status
  * Link status update/event

* **Added feature supports for live migration from vhost-net to vhost-user.**

  Added feature supports for vhost-user to make live migration from vhost-net
  to vhost-user possible. The features include:

  * ``VIRTIO_F_ANY_LAYOUT``
  * ``VIRTIO_F_EVENT_IDX``
  * ``VIRTIO_NET_F_GUEST_ECN``, ``VIRTIO_NET_F_HOST_ECN``
  * ``VIRTIO_NET_F_GUEST_UFO``, ``VIRTIO_NET_F_HOST_UFO``
  * ``VIRTIO_NET_F_GSO``

  Also added ``VIRTIO_NET_F_GUEST_ANNOUNCE`` feature support in virtio pmd.
  In a scenario where the vhost backend doesn't have the ability to generate
  RARP packets, the VM running virtio pmd can still be live migrated if
  ``VIRTIO_NET_F_GUEST_ANNOUNCE`` feature is negotiated.

* **Updated the AESNI-MB PMD.**

  The AESNI-MB PMD has been updated with additional support for:

  * AES-CCM algorithm.

* **Updated the DPAA_SEC crypto driver to support rte_security.**

  Updated the ``dpaa_sec`` crypto PMD to support ``rte_security`` lookaside
  protocol offload for IPsec.

* **Added Wireless Base Band Device (bbdev) abstraction.**

  The Wireless Baseband Device library is an acceleration abstraction
  framework for 3gpp Layer 1 processing functions that provides a common
  programming interface for seamless operation on integrated or discrete
  hardware accelerators or using optimized software libraries for signal
  processing.

  The current release only supports 3GPP CRC, Turbo Coding and Rate
  Matching operations, as specified in 3GPP TS 36.212.

  See the :doc:`../prog_guide/bbdev` programmer's guide for more details.

* **Added New eventdev Ordered Packet Distribution Library (OPDL) PMD.**

  The OPDL (Ordered Packet Distribution Library) eventdev is a specific
  implementation of the eventdev API. It is particularly suited to packet
  processing workloads that have high throughput and low latency requirements.
  All packets follow the same path through the device. The order in which
  packets follow is determined by the order in which queues are set up.
  Events are left on the ring until they are transmitted. As a result packets
  do not go out of order.

  With this change, applications can use the OPDL PMD via the eventdev api.

* **Added new pipeline use case for dpdk-test-eventdev application.**

  Added a new "pipeline" use case for the ``dpdk-test-eventdev`` application.
  The pipeline case can be used to simulate various stages in a real world
  application from packet receive to transmit while maintaining the packet
  ordering. It can also be used to measure the performance of the event device
  across the stages of the pipeline.

  The pipeline use case has been made generic to work with all the event
  devices based on the capabilities.

* **Updated Eventdev sample application to support event devices based on capability.**

  Updated the Eventdev pipeline sample application to support various types of
  pipelines based on the capabilities of the attached event and ethernet
  devices. Also, renamed the application from software PMD specific
  ``eventdev_pipeline_sw_pmd`` to the more generic ``eventdev_pipeline``.

* **Added Rawdev, a generic device support library.**

  The Rawdev library provides support for integrating any generic device type with
  the DPDK framework. Generic devices are those which do not have a pre-defined
  type within DPDK, for example, ethernet, crypto, event etc.

  A set of northbound APIs have been defined which encompass a generic set of
  operations by allowing applications to interact with device using opaque
  structures/buffers. Also, southbound APIs provide a means of integrating devices
  either as as part of a physical bus (PCI, FSLMC etc) or through ``vdev``.

  See the :doc:`../prog_guide/rawdev` programmer's guide for more details.

* **Added new multi-process communication channel.**

  Added a generic channel in EAL for multi-process (primary/secondary) communication.
  Consumers of this channel need to register an action with an action name to response
  a message received; the actions will be identified by the action name and executed
  in the context of a new dedicated thread for this channel. The list of new APIs:

  * ``rte_mp_register`` and ``rte_mp_unregister`` are for action (un)registration.
  * ``rte_mp_sendmsg`` is for sending a message without blocking for a response.
  * ``rte_mp_request`` is for sending a request message and will block until
    it gets a reply message which is sent from the peer by ``rte_mp_reply``.

* **Added GRO support for VxLAN-tunneled packets.**

  Added GRO support for VxLAN-tunneled packets. Supported VxLAN packets
  must contain an outer IPv4 header and inner TCP/IPv4 headers. VxLAN
  GRO doesn't check if input packets have correct checksums and doesn't
  update checksums for output packets. Additionally, it assumes the
  packets are complete (i.e., ``MF==0 && frag_off==0``), when IP
  fragmentation is possible (i.e., ``DF==0``).

* **Increased default Rx and Tx ring size in sample applications.**

  Increased the default ``RX_RING_SIZE`` and ``TX_RING_SIZE`` to 1024 entries
  in testpmd and the sample applications to give better performance in the
  general case. The user should experiment with various Rx and Tx ring sizes
  for their specific application to get best performance.

* **Added new DPDK build system using the tools "meson" and "ninja" [EXPERIMENTAL].**

  Added support for building DPDK using ``meson`` and ``ninja``, which gives
  additional features, such as automatic build-time configuration, over the
  current build system using ``make``. For instructions on how to do a DPDK build
  using the new system, see the instructions in ``doc/build-sdk-meson.txt``.

  .. note::

      This new build system support is incomplete at this point and is added
      as experimental in this release. The existing build system using ``make``
      is unaffected by these changes, and can continue to be used for this
      and subsequent releases until such time as it's deprecation is announced.


Shared Library Versions
-----------------------

.. Update any library version updated in this release and prepend with a ``+``
   sign, like this:

     librte_acl.so.2
   + librte_cfgfile.so.2
     librte_cmdline.so.2

   This section is a comment. do not overwrite or remove it.
   =========================================================


The libraries prepended with a plus sign were incremented in this version.

.. code-block:: diff

     librte_acl.so.2
   + librte_bbdev.so.1
     librte_bitratestats.so.2
     librte_bus_dpaa.so.1
     librte_bus_fslmc.so.1
     librte_bus_pci.so.1
     librte_bus_vdev.so.1
     librte_cfgfile.so.2
     librte_cmdline.so.2
     librte_cryptodev.so.4
     librte_distributor.so.1
     librte_eal.so.6
     librte_ethdev.so.8
     librte_eventdev.so.3
     librte_flow_classify.so.1
     librte_gro.so.1
     librte_gso.so.1
     librte_hash.so.2
     librte_ip_frag.so.1
     librte_jobstats.so.1
     librte_kni.so.2
     librte_kvargs.so.1
     librte_latencystats.so.1
     librte_lpm.so.2
     librte_mbuf.so.3
     librte_mempool.so.3
     librte_meter.so.1
     librte_metrics.so.1
     librte_net.so.1
     librte_pci.so.1
     librte_pdump.so.2
     librte_pipeline.so.3
     librte_pmd_bnxt.so.2
     librte_pmd_bond.so.2
     librte_pmd_i40e.so.2
     librte_pmd_ixgbe.so.2
     librte_pmd_ring.so.2
     librte_pmd_softnic.so.1
     librte_pmd_vhost.so.2
     librte_port.so.3
     librte_power.so.1
   + librte_rawdev.so.1
     librte_reorder.so.1
     librte_ring.so.1
     librte_sched.so.1
     librte_security.so.1
     librte_table.so.3
     librte_timer.so.1
     librte_vhost.so.3



Tested Platforms
----------------

.. This section should contain a list of platforms that were tested with this
   release.

   The format is:

   * <vendor> platform with <vendor> <type of devices> combinations

     * List of CPU
     * List of OS
     * List of devices
     * Other relevant details...

   This section is a comment. do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================

* Intel(R) platforms with Intel(R) NICs combinations

   * CPU

     * Intel(R) Atom(TM) CPU C2758 @ 2.40GHz
     * Intel(R) Xeon(R) CPU D-1540 @ 2.00GHz
     * Intel(R) Xeon(R) CPU D-1541 @ 2.10GHz
     * Intel(R) Xeon(R) CPU E5-4667 v3 @ 2.00GHz
     * Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
     * Intel(R) Xeon(R) CPU E5-2699 v4 @ 2.20GHz
     * Intel(R) Xeon(R) CPU E5-2695 v4 @ 2.10GHz
     * Intel(R) Xeon(R) CPU E5-2658 v2 @ 2.40GHz
     * Intel(R) Xeon(R) CPU E5-2658 v3 @ 2.20GHz
     * Intel(R) Xeon(R) Platinum 8180 CPU @ 2.50GHz

   * OS:

     * CentOS 7.2
     * Fedora 25
     * Fedora 26
     * Fedora 27
     * FreeBSD 11
     * Red Hat Enterprise Linux Server release 7.3
     * SUSE Enterprise Linux 12
     * Wind River Linux 8
     * Ubuntu 14.04
     * Ubuntu 16.04
     * Ubuntu 16.10
     * Ubuntu 17.10

   * NICs:

     * Intel(R) 82599ES 10 Gigabit Ethernet Controller

       * Firmware version: 0x61bf0001
       * Device id (pf/vf): 8086:10fb / 8086:10ed
       * Driver version: 5.2.3 (ixgbe)

     * Intel(R) Corporation Ethernet Connection X552/X557-AT 10GBASE-T

       * Firmware version: 0x800003e7
       * Device id (pf/vf): 8086:15ad / 8086:15a8
       * Driver version: 4.4.6 (ixgbe)

     * Intel(R) Ethernet Converged Network Adapter X710-DA4 (4x10G)

       * Firmware version: 6.01 0x80003221
       * Device id (pf/vf): 8086:1572 / 8086:154c
       * Driver version: 2.4.3 (i40e)

     * Intel Corporation Ethernet Connection X722 for 10GBASE-T

       * firmware-version: 6.01 0x80003221
       * Device id: 8086:37d2 / 8086:154c
       * Driver version: 2.4.3 (i40e)

     * Intel(R) Ethernet Converged Network Adapter XXV710-DA2 (2x25G)

       * Firmware version: 6.01 0x80003221
       * Device id (pf/vf): 8086:158b / 8086:154c
       * Driver version: 2.4.3 (i40e)

     * Intel(R) Ethernet Converged Network Adapter XL710-QDA2 (2X40G)

       * Firmware version: 6.01 0x8000321c
       * Device id (pf/vf): 8086:1583 / 8086:154c
       * Driver version: 2.4.3 (i40e)

     * Intel(R) Corporation I350 Gigabit Network Connection

       * Firmware version: 1.63, 0x80000dda
       * Device id (pf/vf): 8086:1521 / 8086:1520
       * Driver version: 5.3.0-k (igb)

* Intel(R) platforms with Mellanox(R) NICs combinations

   * CPU:

     * Intel(R) Xeon(R) CPU E5-2697A v4 @ 2.60GHz
     * Intel(R) Xeon(R) CPU E5-2697 v3 @ 2.60GHz
     * Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
     * Intel(R) Xeon(R) CPU E5-2650 v4 @ 2.20GHz
     * Intel(R) Xeon(R) CPU E5-2640 @ 2.50GHz
     * Intel(R) Xeon(R) CPU E5-2620 v4 @ 2.10GHz

   * OS:

     * Red Hat Enterprise Linux Server release 7.5 Beta (Maipo)
     * Red Hat Enterprise Linux Server release 7.4 (Maipo)
     * Red Hat Enterprise Linux Server release 7.3 (Maipo)
     * Red Hat Enterprise Linux Server release 7.2 (Maipo)
     * Ubuntu 17.10
     * Ubuntu 16.10
     * Ubuntu 16.04

   * MLNX_OFED: 4.2-1.0.0.0
   * MLNX_OFED: 4.3-0.1.6.0

   * NICs:

     * Mellanox(R) ConnectX(R)-3 Pro 40G MCX354A-FCC_Ax (2x40G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1007
       * Firmware version: 2.42.5000

     * Mellanox(R) ConnectX(R)-4 10G MCX4111A-XCAT (1x10G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 10G MCX4121A-XCAT (2x10G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 25G MCX4111A-ACAT (1x25G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 25G MCX4121A-ACAT (2x25G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 40G MCX4131A-BCAT/MCX413A-BCAT (1x40G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 40G MCX415A-BCAT (1x40G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 50G MCX4131A-GCAT/MCX413A-GCAT (1x50G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 50G MCX414A-BCAT (2x50G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 50G MCX415A-GCAT/MCX416A-BCAT/MCX416A-GCAT (2x50G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 50G MCX415A-CCAT (1x100G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 100G MCX416A-CCAT (2x100G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 Lx 10G MCX4121A-XCAT (2x10G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1015
       * Firmware version: 14.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 Lx 25G MCX4121A-ACAT (2x25G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1015
       * Firmware version: 14.21.1000 and above

     * Mellanox(R) ConnectX(R)-5 100G MCX556A-ECAT (2x100G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1017
       * Firmware version: 16.21.1000 and above

     * Mellanox(R) ConnectX-5 Ex EN 100G MCX516A-CDAT (2x100G)

       * Host interface: PCI Express 4.0 x16
       * Device ID: 15b3:1019
       * Firmware version: 16.21.1000 and above

* ARM platforms with Mellanox(R) NICs combinations

   * CPU:

     * Qualcomm ARM 1.1 2500MHz

   * OS:

     * Ubuntu 16.04

   * MLNX_OFED: 4.2-1.0.0.0

   * NICs:

     * Mellanox(R) ConnectX(R)-4 Lx 25G MCX4121A-ACAT (2x25G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1015
       * Firmware version: 14.21.1000

     * Mellanox(R) ConnectX(R)-5 100G MCX556A-ECAT (2x100G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1017
       * Firmware version: 16.21.1000

Fixes in 18.02 Stable Release
-----------------------------

18.02.1
~~~~~~~

* examples/vhost: move to safe GPA translation API
* examples/vhost_scsi: move to safe GPA translation API
* vhost: add support for non-contiguous indirect descs tables (fixes CVE-2018-1059)
* vhost: check all range is mapped when translating GPAs (fixes CVE-2018-1059)
* vhost: deprecate unsafe GPA translation API (fixes CVE-2018-1059)
* vhost: ensure all range is mapped when translating QVAs (fixes CVE-2018-1059)
* vhost: fix indirect descriptors table translation size (fixes CVE-2018-1059)
* vhost: handle virtually non-contiguous buffers in Rx (fixes CVE-2018-1059)
* vhost: handle virtually non-contiguous buffers in Rx-mrg (fixes CVE-2018-1059)
* vhost: handle virtually non-contiguous buffers in Tx (fixes CVE-2018-1059)
* vhost: introduce safe API for GPA translation (fixes CVE-2018-1059)

18.02.2
~~~~~~~

* app/bbdev: fix unchecked return value
* app/bbdev: use strcpy for allocated string
* app/crypto-perf: check minimum lcore number
* app/crypto-perf: fix burst size calculation
* app/crypto-perf: fix excess crypto device error
* app/crypto-perf: fix IOVA translation
* app/crypto-perf: fix parameters copy
* app/crypto-perf: use strcpy for allocated string
* app/procinfo: fix sprintf overrun
* app/procinfo: fix strncpy usage in args parsing
* app/testpmd: check if CRC strip offload supported
* app/testpmd: fix asynchronic port removal
* app/testpmd: fix build without i40e
* app/testpmd: fix burst stats reporting
* app/testpmd: fix command token
* app/testpmd: fix copy of raw flow item
* app/testpmd: fix DPAA shared library dependency
* app/testpmd: fix empty list of RSS queues for flow
* app/testpmd: fix exit for virtio-user
* app/testpmd: fix flow completion for RSS queues
* app/testpmd: fix forward ports Rx flush
* app/testpmd: fix forward ports update
* app/testpmd: fix lack of flow action configuration
* app/testpmd: fix missing boolean values in flow command
* app/testpmd: fix missing RSS fields in flow action
* app/testpmd: fix port id type
* app/testpmd: fix removed device link status asking
* app/testpmd: fix RSS flow action configuration
* app/testpmd: fix slave port detection
* app/testpmd: fix synchronic port hotplug
* app/testpmd: fix valid ports prints
* app/testpmd: revert fix exit for virtio-user
* bitratestats: fix library version in meson build
* build: fix default arm64 instruction level
* bus/dpaa: fix big endian build
* bus/dpaa: fix inconsistent struct alignment
* bus/dpaa: fix resource leak
* bus/dpaa: fix unchecked return value
* bus/fslmc: do not needlessly check for IOVA mode
* bus/fslmc: fix build with clang 3.4
* bus/fslmc: fix find device start condition
* bus/fslmc: fix memory leak and cleanup
* bus/fslmc: remove dead code
* bus/pci: fix find device implementation
* bus/pci: fix size of driver name buffer
* bus/vdev: fix double space in logs
* bus/vdev: fix find device implementation
* bus/vdev: fix finding device by name
* config: remove old log level option
* crypto/aesni_gcm: remove unneeded cast
* crypto/armv8: fix HMAC supported digest sizes
* cryptodev: add missing security feature string
* cryptodev: fix library version in meson build
* cryptodev: fix supported size check
* crypto/dpaa2_sec: fix debug logs
* crypto/dpaa2_sec: fix HMAC supported digest sizes
* crypto/dpaa2_sec: fix OP storage for physical IOVA mode
* crypto/dpaa2_sec: improve error handling
* crypto/dpaa2_sec: remove IOVA conversion for fle address
* crypto/dpaa_sec: add macro for device name
* crypto/dpaa_sec: add portal presence check
* crypto/dpaa_sec: fix HMAC supported digest sizes
* crypto/dpaa_sec: fix null check in uninit
* crypto/dpaa_sec: improve the error checking
* crypto/qat: assign device to correct NUMA node
* crypto/scheduler: fix 64-bit mask of workers cores
* crypto/scheduler: fix memory leak
* crypto/scheduler: fix multicore rings re-use
* crypto/scheduler: fix possible duplicated ring names
* crypto/scheduler: set null pointer after freeing
* crypto/zuc: batch ops with same transform
* crypto/zuc: do not set default op status
* crypto/zuc: remove unnecessary check
* doc: adapt features tables header height
* doc: add timestamp offload to mlx5 features
* doc: fix a typo in flow API howto
* doc: fix a typo in rawdev guide
* doc: fix a typo in the EAL guide
* doc: fix NFP NIC guide grammar
* doc: fix typos in OcteonTx guides
* doc: reduce features tables column width
* doc: reduce initial offload API rework scope to drivers
* doc: remove deprecated terms from thunderx guide
* drivers: fix build issue with DPAA2 drivers
* drivers/net: fix icc deprecated parameter warning
* drivers/net: fix link autoneg value for virtual PMDs
* drivers/net: remove redundant icc flag
* drivers/net: use higher level of probing helper for PCI
* eal: declare trace buffer at top of own block
* eal: explicit cast in constant byte swap
* eal: explicit cast in rwlock functions
* eal: explicit cast of builtin for bsf32
* eal: explicit cast of core id when getting index
* eal: fix casts in random functions
* eal: fix errno handling in IPC
* eal: fix IPC request socket path
* eal: fix IPC socket path
* eal: fix IPC timeout
* eal: fix mempool ops name parsing
* eal: fix race condition in IPC request
* eal: fix typo in doc of pointer offset macro
* eal/ppc: remove braces in SMP memory barrier macro
* eal: remove unused path pattern
* eal: support strlcpy function
* eal/x86: fix type of variable in memcpy function
* ethdev: add doxygen comments for each state
* ethdev: add lock to port allocation check
* ethdev: add missing TM function to export map
* ethdev: add probing finish function
* ethdev: allow ownership operations on unused port
* ethdev: explicit cast of buffered Tx number
* ethdev: explicit cast of queue count return
* ethdev: fix debug log of owner id
* ethdev: fix missing include in flow API
* ethdev: fix port accessing after release
* ethdev: fix port probing notification
* ethdev: fix port removal notification timing
* ethdev: fix port visibility before initialization
* ethdev: fix queue start
* ethdev: fix shallow copy of flow API RSS action
* ethdev: fix storage type of latest port id
* ethdev: fix string length in name comparison
* ethdev: fix type and scope of variables in Rx burst
* ethdev: improve doc for name by port ID API
* ethdev: remove unused struct forward declaration
* eventdev: fix library version in meson build
* eventdev: fix MP/MC tail updates in event ring
* eventdev: remove stale forward declaration
* event/dpaa2: remove check on epoll return
* event/dpaa2: remove link from info structure
* event/dpaa: fix header include
* event/dpaa: fix integer overflow of max ports
* event/opdl: fix atomic queue race condition
* examples/exception_path: limit core count to 64
* examples/flow_classify: fix validation in port init
* examples/ipsec-secgw: fix usage print
* examples/l2fwd-crypto: fix the default aead assignments
* examples/performance-thread: fix return type of threads
* examples/quota_watermark: fix return type of threads
* fix ethdev port id validation
* fix ethdev ports enumeration
* hash: explicit casts for truncation in CRC32c
* hash: fix comment for lookup
* hash: fix missing spinlock unlock in add key
* hash: move stack declaration at top of CRC32c function
* igb_uio: pass MODULE_CFLAGS in Kbuild
* ipc: fix missing mutex unlocks on failed send
* ipc: fix use-after-free in synchronous requests
* ip_frag: fix double free of chained mbufs
* ip_frag: fix some debug logs
* kni: fix build on RHEL 7.5
* kvargs: fix syntax in comments
* mbuf: avoid implicit demotion in 64-bit arithmetic
* mbuf: avoid integer promotion in prepend/adj/chain
* mbuf: explicit cast of headroom on reset
* mbuf: explicit cast of size on detach
* mbuf: explicit casts of reference counter
* mbuf: fix reference counter integer promotion
* mbuf: fix truncated strncpy
* mbuf: fix Tx checksum offload API doc
* mbuf: fix type of private size in detach
* mbuf: fix type of variables in linearize function
* mbuf: improve tunnel Tx offloads API doc
* mem: do not use physical addresses in IOVA as VA mode
* mempool: fix leak when no objects are populated
* mempool: fix library version in meson build
* mempool: fix virtual address population
* memzone: fix size on reserving biggest memzone
* mk: fix dependencies of dpaaX drivers
* mk: fix make defconfig on FreeBSD
* net/avf: fix link autoneg value
* net/avf: fix Rx interrupt mapping
* net/avf: fix traffic blocked on reset
* net/bnx2x: do not cast function pointers as a policy
* net/bnx2x: fix for PCI FLR after ungraceful exit
* net/bnx2x: fix KR2 device check
* net/bnx2x: fix memzone name overrun
* net/bnxt: add device ID for Stratus VF
* net/bnxt: avoid freeing memzone multiple times
* net/bnxt: avoid invalid vnic id in set L2 Rx mask
* net/bnxt: fix endianness of flag
* net/bnxt: fix flow destroy
* net/bnxt: fix flow director with same cmd different queue
* net/bnxt: fix incorrect ntuple flag setting
* net/bnxt: fix L2 filter cleanup
* net/bnxt: fix license header
* net/bnxt: fix LRO disable
* net/bnxt: fix matching of flow API item masks
* net/bnxt: fix mbuf data offset initialization
* net/bnxt: fix MTU calculation
* net/bnxt: fix Rx checksum flags
* net/bnxt: fix Rx checksum flags for tunnel frames
* net/bnxt: fix Rx drop setting
* net/bnxt: fix Rx mbuf and agg ring leak in dev stop
* net/bnxt: fix to reset status of initialization
* net/bnxt: fix Tx and Rx burst for secondary process
* net/bnxt: fix usage of vnic id
* net/bnxt: fix xstats for VF
* net/bnxt: free memory allocated for VF filters
* net/bnxt: reset L2 filter id once filter is freed
* net/bnxt: return error in stats if init is not complete
* net/bnxt: set MTU in dev config for jumbo packets
* net/bnxt: set padding flags in Rx descriptor
* net/bnxt: use first completion ring for fwd and async event
* net/bonding: clear started state if start fails
* net/bonding: export mode 4 slave info routine
* net/bonding: fix library version in meson build
* net/bonding: fix primary slave port id storage type
* net/bonding: fix setting VLAN ID on slave ports
* net/bonding: fix slave activation simultaneously
* net/bonding: fix typo in log comment
* net/bonding: free mempool used in mode 6
* net/cxgbe: fix secondary process initialization
* net/dpaa2: fix xstats
* net/dpaa: fix array overrun
* net/dpaa: fix max push mode queue
* net/dpaa: fix oob access
* net/dpaa: fix RSS hash support
* net/dpaa: fix xstats implementation
* net/e1000: fix build of igb only
* net/enic: allocate stats DMA buffer upfront during probe
* net/enic: fix crash on MTU update with non-setup queues
* net/enic: set rte errno to positive value
* net: explicit cast in L4 checksum
* net: explicit cast of IP checksum to 16-bit
* net: explicit cast of multicast bit clearing
* net: explicit cast of protocol in IPv6 checksum
* net/failsafe: fix duplicate event registration
* net/failsafe: fix probe cleanup
* net/failsafe: fix removed sub-device cleanup
* net/failsafe: fix sub-device ownership race
* net/failsafe: fix sub-device visibility
* net/i40e: add comment and clean code for flow RSS
* net/i40e: fix DDP profile DEL operation
* net/i40e: fix failing to disable FDIR Tx queue
* net/i40e: fix flow RSS configuration error
* net/i40e: fix flow RSS queue index check
* net/i40e: fix flow RSS queue region
* net/i40e: fix flow RSS TCI use
* net/i40e: fix intr callback unregister by adding retry
* net/i40e: fix library version in meson build
* net/i40e: fix link status update
* net/i40e: fix link status update
* net/i40e: fix link update no wait
* net/i40e: fix missing defines for non-AVX build
* net/i40e: fix shifts of signed values
* net/i40e: fix support DDP packages group 0xff
* net/i40e: fix using error set function
* net/i40e: print global register change info
* net/i40e: print original value for global register change
* net/igb: fix flow RSS queue index
* net/ixgbe: enable vector PMD for icc 32 bits
* net/ixgbe: fix busy wait during checking link status
* net/ixgbe: fix DCB configuration
* net/ixgbe: fix intr callback unregister by adding retry
* net/ixgbe: fix library version in meson build
* net/ixgbe: fix too many interrupts
* net/liquidio: fix link state fetching during start
* net/mlx4: fix a typo in header file
* net/mlx4: fix default RSS hash fields
* net/mlx4: fix ignored RSS hash types
* net/mlx4: fix inner RSS support for broken kernels
* net/mlx4: fix RSS resource leak in case of error
* net/mlx4: fix Rx resource leak in case of error
* net/mlx4: fix shifts of signed values in Tx
* net/mlx4: fix UDP flow rule limitation enforcement
* net/mlx5: add missing function documentation
* net/mlx5: change non failing function return values
* net/mlx5: enforce RSS key length limitation
* net/mlx5: fix ARM build
* net/mlx5: fix build with clang on ARM
* net/mlx5: fix calculation of Tx TSO inline room size
* net/mlx5: fix disabling Tx packet inlining
* net/mlx5: fix double free on error handling
* net/mlx5: fix ethtool link setting call order
* net/mlx5: fix existing file removal
* net/mlx5: fix flow creation with a single target queue
* net/mlx5: fix flow director drop rule deletion crash
* net/mlx5: fix flow director mask
* net/mlx5: fix flow director rule deletion crash
* net/mlx5: fix flow validation
* net/mlx5: fix icc build
* net/mlx5: fix inlining segmented TSO packet
* net/mlx5: fix link status behavior
* net/mlx5: fix link status initialization
* net/mlx5: fix link status to use wait to complete
* net/mlx5: fix probe return value polarity
* net/mlx5: fix resource leak in case of error
* net/mlx5: fix RSS flow action bounds check
* net/mlx5: fix RSS key length query
* net/mlx5: fix socket connection return value
* net/mlx5: fix sriov flag
* net/mlx5: fix TSO enablement
* net/mlx5: fix tunnel offloads cap query
* net/mlx5: mark parameters with unused attribute
* net/mlx5: name parameters in function prototypes
* net/mlx5: normalize function prototypes
* net/mlx5: prefix all functions with mlx5
* net/mlx5: remove control path locks
* net/mlx5: remove kernel version check
* net/mlx5: remove useless empty lines
* net/mlx5: revert to older logging macros
* net/mlx5: split L3/L4 in flow director
* net/mlx5: standardize on negative errno values
* net/mlx: control netdevices through ioctl only
* net/mlx: fix rdma-core glue path with EAL plugins
* net/mlx: fix warnings for unused compiler arguments
* net: move stack variable at top of VLAN strip function
* net/mrvl: fix crash when port is closed without starting
* net/mrvl: fix Rx descriptors number
* net/mrvl: fix typo in log message
* net/nfp: fix assigning port id in mbuf
* net/nfp: fix barrier location
* net/nfp: fix double space in init log
* net/nfp: fix link speed capabilities
* net/nfp: fix mbufs releasing when stop or close
* net/nfp: fix memcpy out of source range
* net/null: fix library version in meson build
* net/octeontx: fix null pointer dereference
* net/octeontx: fix uninitialized speed variable
* net/octeontx: fix uninitialized variable in port open
* net/octeontx: remove redundant driver name update
* net/qede: fix alloc from socket 0
* net/qede: fix device stop to remove primary MAC
* net/qede: fix missing loop index in Tx SG mode
* net/qede: fix multicast filtering
* net/qede: fix slow path completion timeout
* net/qede: fix strncpy
* net/qede: fix to prevent overwriting packet type
* net/qede: fix unicast filter routine return code
* net/qede: replace strncpy by strlcpy
* net/ring: fix library version in meson build
* net/sfc: add missing defines for SAL annotation
* net/sfc: add missing Rx fini on RSS setup fail path
* net/sfc/base: fix comparison always true warning
* net/sfc/base: fix too long line
* net/sfc: fix errno if flow API RSS action parse fails
* net/sfc: fix inner TCP/UDP checksum offload control
* net/sfc: fix mbuf data alignment calculation
* net/sfc: fix type of opaque pointer in perf profile handler
* net/sfc: ignore spec bits not covered by mask
* net/sfc: make sure that stats name is nul-terminated
* net/sfc: process RSS settings on Rx configure step
* net/szedata2: fix format string for PCI address
* net/szedata2: fix total stats
* net/tap: fix device removal when no queue exist
* net/tap: fix icc build
* net/tap: fix isolation mode toggling
* net/tap: fix keep-alive queue not detached
* net/tap: return empty port offload capabilities
* net/thunderx: fix MTU configuration for jumbo packets
* net/vdev_netvsc: add check for specifying by 1 way
* net/vdev_netvsc: fix automatic probing
* net/vdev_netvsc: fix routed devices probing
* net/vdev_netvsc: prefer netvsc devices in scan
* net/vdev_netvsc: readlink inputs cannot be aliased
* net/vdev_netvsc: remove specified devices IP check
* net/vhost: fix crash when creating vdev dynamically
* net/vhost: fix invalid state
* net/vhost: initialise device as inactive
* net/virtio: fix queues pointer check
* net/virtio-user: fix hugepage files enumeration
* net/virtio-user: fix port id type
* net/vmxnet3: fix Rx offload information in multiseg packets
* net/vmxnet3: gather offload data on first and last segment
* net/vmxnet3: keep link state consistent
* net/vmxnet3: set the queue shared buffer at start
* nfp: allow for non-root user
* nfp: restore the unlink operation
* nfp: unlink the appropriate lock file
* pci: remove duplicated symbol from map file
* pdump: fix library version in meson build
* rawdev: remove dead code
* raw/skeleton: fix resource leak in test
* raw/skeleton: remove dead code
* ring: remove signed type flip-flopping
* ring: remove useless variables
* spinlock/x86: move stack declaration before code
* table: fix library version in meson build
* test/crypto: add macro for dpaa device name
* test/crypto: add MRVL to hash test cases
* test/distributor: fix return type of thread function
* test/eventdev: fix ethdev port id to 16-bit
* test: fix memory flags test for low NUMA nodes number
* test/mempool: fix autotest retry
* test/pipeline: fix return type of stub miss
* test/pipeline: fix type of table entry parameter
* test/reorder: fix freeing mbuf twice
* vfio: do not needlessly check for IOVA mode
* vfio: export functions even when disabled
* vfio: fix device hotplug when several devices per group
* vfio: fix headers for C++ support
* vhost: check cmsg not null
* vhost: fix compilation issue when vhost debug enabled
* vhost: fix dead lock on closing in server mode
* vhost: fix device cleanup at stop
* vhost: fix log macro name conflict
* vhost: fix message payload union in setting ring address
* vhost: fix offset while mmaping log base address
* vhost: fix realloc failure
* vhost: fix ring index returned to master on stop
* vhost: fix typo in comment
* vhost: improve dirty pages logging performance
