import Foundation

enum StorefrontRegions {
    struct Region: Identifiable {
        let id: String
        let name: String
        let codes: [String]
        let names: [String]
    }

    static let common = ["US", "CN", "JP", "HK", "TW", "DE", "GB", "KR"]
    private static let chinese = Locale(identifier: "zh-Hans")
    private static let traditionalChinese = Locale(identifier: "zh-Hant")
    private static let english = Locale(identifier: "en")
    private static let displayNames = [
        "US": "美国", "CN": "中国", "JP": "日本", "HK": "香港", "TW": "台湾",
        "DE": "德国", "GB": "英国", "KR": "韩国", "MO": "澳门"
    ]
    private static let additionalNames = [
        "US": ["USA", "America", "美区"], "GB": ["UK", "英区"], "CN": ["中国大陆", "中國大陸", "大陆", "国区"],
        "JP": ["日区"], "HK": ["港区"], "TW": ["臺灣", "台区"], "AE": ["UAE", "阿联酋"]
    ]

    static let all: [Region] = regionData.split(whereSeparator: \.isNewline).map { row in
        let codes = row.split(separator: " ").map(String.init)
        let id = codes[0]
        let names = [chinese, traditionalChinese, english, Locale.current].compactMap { $0.localizedString(forRegionCode: id) }
        let name = displayNames[id] ?? names.first ?? id
        return Region(id: id, name: name, codes: codes, names: [name] + names + (additionalNames[id] ?? []))
    }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }

    private static let regionsByCode = Dictionary(uniqueKeysWithValues: all.map { ($0.id, $0) })
    private static let regionsByIdentifier = Dictionary(uniqueKeysWithValues: all.flatMap { region in
        region.codes.map { ($0, region) }
    })

    static func name(for code: String) -> String { regionsByCode[code]?.name ?? code }

    static func defaultCountry(for storeFront: String?) -> String {
        country(forStoreFront: storeFront) ?? "US"
    }

    static func country(forStoreFront storeFront: String?) -> String? {
        let id = (storeFront ?? "").split(whereSeparator: { $0 == "," || $0 == "-" }).first?
            .trimmingCharacters(in: .whitespacesAndNewlines).uppercased() ?? ""
        return regionsByIdentifier[id]?.id
    }

    static func defaultOrder(current: String) -> [Region] {
        let pinned = common.contains(current) ? common : common + [current]
        return pinned.compactMap { regionsByCode[$0] } + all.filter { !pinned.contains($0.id) }
    }

    static func matches(_ input: String) -> [Region] {
        let query = normalized(input)
        guard !query.isEmpty else { return [] }
        if let exact = regionsByIdentifier[query.uppercased()] { return [exact] }
        let exactNames = all.filter { $0.names.contains { normalized($0) == query } }
        if !exactNames.isEmpty { return exactNames }
        return all.filter { region in
            region.names.contains { normalized($0).contains(query) } ||
                region.codes.contains { $0.lowercased().hasPrefix(query) }
        }
    }

    private static func normalized(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
            .folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: english)
            .lowercased()
    }

    // App Store storefront IDs from the 2026-09 Storelift measurements and the
    // vendored ipatool table. ISO codes come from Unicode CLDR territoryCodes.
    private static let regionData = """
        AE ARE 784 143481
        AF AFG 004 143610
        AG ATG 028 143540
        AI AIA 660 143538
        AL ALB 008 143575
        AM ARM 051 143524
        AO AGO 024 143564
        AR ARG 032 143505
        AT AUT 040 143445
        AU AUS 036 143460
        AZ AZE 031 143568
        BA BIH 070 143612
        BB BRB 052 143541
        BD BGD 050 143490
        BE BEL 056 143446
        BF BFA 854 143578
        BG BGR 100 143526
        BH BHR 048 143559
        BJ BEN 204 143576
        BM BMU 060 143542
        BN BRN 096 143560
        BO BOL 068 143556
        BR BRA 076 143503
        BS BHS 044 143539
        BT BTN 064 143577
        BW BWA 072 143525
        BY BLR 112 143565
        BZ BLZ 084 143555
        CA CAN 124 143455
        CD COD 180 143613
        CG COG 178 143582
        CH CHE 756 143459
        CI CIV 384 143527
        CL CHL 152 143483
        CM CMR 120 143574
        CN CHN 156 143465
        CO COL 170 143501
        CR CRI 188 143495
        CV CPV 132 143580
        CY CYP 196 143557
        CZ CZE 203 143489
        DE DEU 276 143443
        DK DNK 208 143458
        DM DMA 212 143545
        DO DOM 214 143508
        DZ DZA 012 143563
        EC ECU 218 143509
        EE EST 233 143518
        EG EGY 818 143516
        ES ESP 724 143454
        FI FIN 246 143447
        FJ FJI 242 143583
        FM FSM 583 143591
        FR FRA 250 143442
        GA GAB 266 143614
        GB GBR 826 143444
        GD GRD 308 143546
        GE GEO 268 143615
        GH GHA 288 143573
        GM GMB 270 143584
        GR GRC 300 143448
        GT GTM 320 143504
        GW GNB 624 143585
        GY GUY 328 143553
        HK HKG 344 143463
        HN HND 340 143510
        HR HRV 191 143494
        HU HUN 348 143482
        ID IDN 360 143476
        IE IRL 372 143449
        IL ISR 376 143491
        IN IND 356 143467
        IQ IRQ 368 143617
        IS ISL 352 143558
        IT ITA 380 143450
        JM JAM 388 143511
        JO JOR 400 143528
        JP JPN 392 143462
        KE KEN 404 143529
        KG KGZ 417 143586
        KH KHM 116 143579
        KN KNA 659 143548
        KR KOR 410 143466
        KW KWT 414 143493
        KY CYM 136 143544
        KZ KAZ 398 143517
        LA LAO 418 143587
        LB LBN 422 143497
        LC LCA 662 143549
        LI LIE 438 143522
        LK LKA 144 143486
        LR LBR 430 143588
        LT LTU 440 143520
        LU LUX 442 143451
        LV LVA 428 143519
        LY LBY 434 143567
        MA MAR 504 143620
        MD MDA 498 143523
        ME MNE 499 143619
        MG MDG 450 143531
        MK MKD 807 143530
        ML MLI 466 143532
        MM MMR 104 143570
        MN MNG 496 143592
        MO MAC 446 143515
        MR MRT 478 143590
        MS MSR 500 143547
        MT MLT 470 143521
        MU MUS 480 143533
        MV MDV 462 143488
        MW MWI 454 143589
        MX MEX 484 143468
        MY MYS 458 143473
        MZ MOZ 508 143593
        NA NAM 516 143594
        NE NER 562 143534
        NG NGA 566 143561
        NI NIC 558 143512
        NL NLD 528 143452
        NO NOR 578 143457
        NP NPL 524 143484
        NR NRU 520 143606
        NZ NZL 554 143461
        OM OMN 512 143562
        PA PAN 591 143485
        PE PER 604 143507
        PG PNG 598 143597
        PH PHL 608 143474
        PK PAK 586 143477
        PL POL 616 143478
        PT PRT 620 143453
        PW PLW 585 143595
        PY PRY 600 143513
        QA QAT 634 143498
        RO ROU 642 143487
        RS SRB 688 143500
        RU RUS 643 143469
        RW RWA 646 143621
        SA SAU 682 143479
        SB SLB 090 143601
        SC SYC 690 143599
        SE SWE 752 143456
        SG SGP 702 143464
        SI SVN 705 143499
        SK SVK 703 143496
        SL SLE 694 143600
        SN SEN 686 143535
        SR SUR 740 143554
        ST STP 678 143598
        SV SLV 222 143506
        SZ SWZ 748 143602
        TC TCA 796 143552
        TD TCD 148 143581
        TH THA 764 143475
        TJ TJK 762 143603
        TM TKM 795 143604
        TN TUN 788 143536
        TO TON 776 143608
        TR TUR 792 143480
        TT TTO 780 143551
        TW TWN 158 143470
        TZ TZA 834 143572
        UA UKR 804 143492
        UG UGA 800 143537
        US USA 840 143441
        UY URY 858 143514
        UZ UZB 860 143566
        VC VCT 670 143550
        VE VEN 862 143502
        VG VGB 092 143543
        VN VNM 704 143471
        VU VUT 548 143609
        XK XKK 983 143624
        YE YEM 887 143571
        ZA ZAF 710 143472
        ZM ZMB 894 143622
        ZW ZWE 716 143605
        """
}
