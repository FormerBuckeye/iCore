# iCore: Continuous and Proactive Extrospection on Multi-core IoT Devices

## Brief

- This repository contains source code for iCore paper.
- Modification and improvement are welcomed on iCore prototype.
- The source code in this repository is only for OP-TEE OS part. 
- The rest part can be downloaded following the [instruction](https://github.com/OP-TEE/build) with branch `-b 2.0.0`.

## iCore Architecture

- Dedicated cores are isolated as iCore to perform proactive and continuous extrospection on ARM TrustZone based multi-core platform.
- Evaluation shows that the overhead of the system with iCore is negligible.
- To get full details, See the paper.

## How to build

- Clone OP-TEE version 2.0.0 following the [instruction](https://github.com/OP-TEE/build). `{TARGET}.xml` depends on which development board you are using. In our case, it is `hikey_stable.xml`.
  ```
  $ mkdir -p $HOME/devel/optee
  $ cd $HOME/devel/optee
  $ repo init -u https://github.com/OP-TEE/manifest.git -m ${TARGET}.xml -b 2.0.0
  $ repo sync
  ```
- Replace the `optee_os` folder with the one in this repo.
- You can define the number of CPUs as iCore. For example, change the second operand of `cmp x0, #7` in `LOCAL_FUNC vector_cpu_on_entry` to `#6` in `/{directory of optee}/optee-os/core/arch/arm/kernel/thread_a64.S`, if you would like 2 CPUs isolated as iCore.
- Build the iCore arhitecture as follows:
  ```
  $ cd build
  $ make toolchains
  $ make
  ```
- Flash the built software on your device. Root privilege is optional.
  ```
  $ (sudo) make flash
  ```

## How to test

- By checking `cpuinfo`, the number of CPUs should be (total number of CPUs - number of CPUs as iCore).

  ```
  $ cat /proc/cpuinfo
  ```
- When the data in the static kernel memory region of the normal world is modified, the system will show a warning:
  ```
  WARNING: MALICIOUS MODIFICATION, FURTHER RESPONSE REQUIRED
  ```

<!-- ## Python script to convert bucket-encoded image to real image

- images/py_scrips/*.py are scripts to convert bucket-encoded image to real image.
- You can try to convert the bucket-encoded image with below instructions.
  ```
  $ cd images/py_scripts/test/
  $ python ../collect_image_set_counting_mode.py 01.csv (01.csv is prepared bucket-encoded image for testing)
  $ ls -l output.pbm
    (See output.pbm, and compare it to circle.pbm which is original image.)
  ``` -->

<!-- ## Image data

- images/ :  images for experiments. -->

## Full paper

- APPEAR SOON.

<!-- - [Prime+Count: Novel Cross-world Covert Channels on ARM TrustZone](http://www.public.asu.edu/~hcho67/papers/prime+count-acsac18.pdf) -->

## License

- Under GPLv2.
- Copyrights are specificed under LICENSE.

## Contact

- Penghui Zhang <Penghui.Zhang@asu.edu>
<!-- - Jinbum Park <jinb.park@samsung.com>, <jinb.park7@gmail.com>
 -->