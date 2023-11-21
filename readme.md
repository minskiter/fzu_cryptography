### 密码学作业

1. 实验1

目录：./h1/

任务说明：
- [x] 实现AES
    ```bash
    CIPHER (ENCRYPT): 
    round[ 0].input          00112233445566778899aabbccddeeff
    round[ 0].k_sch          000102030405060708090a0b0c0d0e0f
    round[ 1].start          00102030405060708090a0b0c0d0e0f0
    round[ 1].s_box          63cab7040953d051cd60e0e7ba70e18c
    round[ 1].s_row          6353e08c0960e104cd70b751bacad0e7
    round[ 1].m_col          5f72641557f5bc92f7be3b291db9f91a
    round[ 1].k_sch          d6aa74fdd2af72fadaa678f1d6ab76fe
    round[ 2].start          89d810e8855ace682d1843d8cb128fe4
    round[ 2].s_box          a761ca9b97be8b45d8ad1a611fc97369
    round[ 2].s_row          a7be1a6997ad739bd8c9ca451f618b61
    round[ 2].m_col          ff87968431d86a51645151fa773ad009
    round[ 2].k_sch          b692cf0b643dbdf1be9bc5006830b3fe
    round[ 3].start          4915598f55e5d7a0daca94fa1f0a63f7
    round[ 3].s_box          3b59cb73fcd90ee05774222dc067fb68
    round[ 3].s_row          3bd92268fc74fb735767cbe0c0590e2d
    round[ 3].m_col          4c9c1e66f771f0762c3f868e534df256
    round[ 3].k_sch          b6ff744ed2c2c9bf6c590cbf0469bf41
    round[ 4].start          fa636a2825b339c940668a3157244d17
    round[ 4].s_box          2dfb02343f6d12dd09337ec75b36e3f0
    round[ 4].s_row          2d6d7ef03f33e334093602dd5bfb12c7
    round[ 4].m_col          6385b79ffc538df997be478e7547d691
    round[ 4].k_sch          47f7f7bc95353e03f96c32bcfd058dfd
    round[ 5].start          247240236966b3fa6ed2753288425b6c
    round[ 5].s_box          36400926f9336d2d9fb59d23c42c3950
    round[ 5].s_row          36339d50f9b539269f2c092dc4406d23
    round[ 5].m_col          f4bcd45432e554d075f1d6c51dd03b3c
    round[ 5].k_sch          3caaa3e8a99f9deb50f3af57adf622aa
    round[ 6].start          c81677bc9b7ac93b25027992b0261996
    round[ 6].s_box          e847f56514dadde23f77b64fe7f7d490
    round[ 6].s_row          e8dab6901477d4653ff7f5e2e747dd4f
    round[ 6].m_col          9816ee7400f87f556b2c049c8e5ad036
    round[ 6].k_sch          5e390f7df7a69296a7553dc10aa31f6b
    round[ 7].start          c62fe109f75eedc3cc79395d84f9cf5d
    round[ 7].s_box          b415f8016858552e4bb6124c5f998a4c
    round[ 7].s_row          b458124c68b68a014b99f82e5f15554c
    round[ 7].m_col          c57e1c159a9bd286f05f4be098c63439
    round[ 7].k_sch          14f9701ae35fe28c440adf4d4ea9c026
    round[ 8].start          d1876c0f79c4300ab45594add66ff41f
    round[ 8].s_box          3e175076b61c04678dfc2295f6a8bfc0
    round[ 8].s_row          3e1c22c0b6fcbf768da85067f6170495
    round[ 8].m_col          baa03de7a1f9b56ed5512cba5f414d23
    round[ 8].k_sch          47438735a41c65b9e016baf4aebf7ad2
    round[ 9].start          fde3bad205e5d0d73547964ef1fe37f1
    round[ 9].s_box          5411f4b56bd9700e96a0902fa1bb9aa1
    round[ 9].s_row          54d990a16ba09ab596bbf40ea111702f
    round[ 9].m_col          e9f74eec023020f61bf2ccf2353c21c7
    round[ 9].k_sch          549932d1f08557681093ed9cbe2c974e
    round[10].start          bd6e7c3df2b5779e0b61216e8b10b689
    round[10].s_box          7a9f102789d5f50b2beffd9f3dca4ea7
    round[10].s_row          7ad5fda789ef4e272bca100b3d9ff59f
    round[10].m_col          7ad5fda789ef4e272bca100b3d9ff59f
    round[10].k_sch          13111d7fe3944a17f307a78b4d2b30c5
    round[10].output         69c4e0d86a7b0430d8cdb78070b4c55a
    INVERSE CIPHER (DECRYPT):
    round[ 0].iinput         69c4e0d86a7b0430d8cdb78070b4c55a
    round[ 0].ik_sch         13111d7fe3944a17f307a78b4d2b30c5
    round[ 1].istart         7ad5fda789ef4e272bca100b3d9ff59f
    round[ 1].is_row         7a9f102789d5f50b2beffd9f3dca4ea7
    round[ 1].is_box         bd6e7c3df2b5779e0b61216e8b10b689
    round[ 1].ik_sch         549932d1f08557681093ed9cbe2c974e
    round[ 1].im_col         54d990a16ba09ab596bbf40ea111702f
    round[ 2].istart         54d990a16ba09ab596bbf40ea111702f
    round[ 2].is_row         5411f4b56bd9700e96a0902fa1bb9aa1
    round[ 2].is_box         fde3bad205e5d0d73547964ef1fe37f1
    round[ 2].ik_sch         47438735a41c65b9e016baf4aebf7ad2
    round[ 2].im_col         3e1c22c0b6fcbf768da85067f6170495
    round[ 3].istart         3e1c22c0b6fcbf768da85067f6170495
    round[ 3].is_row         3e175076b61c04678dfc2295f6a8bfc0
    round[ 3].is_box         d1876c0f79c4300ab45594add66ff41f
    round[ 3].ik_sch         14f9701ae35fe28c440adf4d4ea9c026
    round[ 3].im_col         b458124c68b68a014b99f82e5f15554c
    round[ 4].istart         b458124c68b68a014b99f82e5f15554c
    round[ 4].is_row         b415f8016858552e4bb6124c5f998a4c
    round[ 4].is_box         c62fe109f75eedc3cc79395d84f9cf5d
    round[ 4].ik_sch         5e390f7df7a69296a7553dc10aa31f6b
    round[ 4].im_col         e8dab6901477d4653ff7f5e2e747dd4f
    round[ 5].istart         e8dab6901477d4653ff7f5e2e747dd4f
    round[ 5].is_row         e847f56514dadde23f77b64fe7f7d490
    round[ 5].is_box         c81677bc9b7ac93b25027992b0261996
    round[ 5].ik_sch         3caaa3e8a99f9deb50f3af57adf622aa
    round[ 5].im_col         36339d50f9b539269f2c092dc4406d23
    round[ 6].istart         36339d50f9b539269f2c092dc4406d23
    round[ 6].is_row         36400926f9336d2d9fb59d23c42c3950
    round[ 6].is_box         247240236966b3fa6ed2753288425b6c
    round[ 6].ik_sch         47f7f7bc95353e03f96c32bcfd058dfd
    round[ 6].im_col         2d6d7ef03f33e334093602dd5bfb12c7
    round[ 7].istart         2d6d7ef03f33e334093602dd5bfb12c7
    round[ 7].is_row         2dfb02343f6d12dd09337ec75b36e3f0
    round[ 7].is_box         fa636a2825b339c940668a3157244d17
    round[ 7].ik_sch         b6ff744ed2c2c9bf6c590cbf0469bf41
    round[ 7].im_col         3bd92268fc74fb735767cbe0c0590e2d
    round[ 8].istart         3bd92268fc74fb735767cbe0c0590e2d
    round[ 8].is_row         3b59cb73fcd90ee05774222dc067fb68
    round[ 8].is_box         4915598f55e5d7a0daca94fa1f0a63f7
    round[ 8].ik_sch         b692cf0b643dbdf1be9bc5006830b3fe
    round[ 8].im_col         a7be1a6997ad739bd8c9ca451f618b61
    round[ 9].istart         a7be1a6997ad739bd8c9ca451f618b61
    round[ 9].is_row         a761ca9b97be8b45d8ad1a611fc97369
    round[ 9].is_box         89d810e8855ace682d1843d8cb128fe4
    round[ 9].ik_sch         d6aa74fdd2af72fadaa678f1d6ab76fe
    round[ 9].im_col         6353e08c0960e104cd70b751bacad0e7
    round[10].istart         6353e08c0960e104cd70b751bacad0e7
    round[10].is_row         63cab7040953d051cd60e0e7ba70e18c
    round[10].is_box         00102030405060708090a0b0c0d0e0f0
    round[10].ik_sch         000102030405060708090a0b0c0d0e0f
    round[10].ioutput        00112233445566778899aabbccddeeff
    ```
- [x] 实现CBC模式
- [x] 实现CFB模式

参考资料：
https://blog.csdn.net/weixin_42580862/article/details/101703941 AES原理
https://blog.csdn.net/hpu11/article/details/108198389 分组加密
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf AES官方文档

2. 实验2
目录：./h2/

任务说明：
- [X] RSA

3. 实验3
目录：./h3/

任务说明：
- [X] SM3
- [X] HMAC

### LICENSE
MIT