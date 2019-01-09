using System;
namespace CVESummaryGenerator
{
    public static class Constants
    {
        public static class SummaryTableColumn
        {
            public static readonly string CveNumber = "CVE";
            public static readonly string CveTitle = "概要";
            public static readonly string Description = "詳細";
            public static readonly string Severity = "深刻度";
            public static readonly string PubliclyDisclosed = "一般に公開";
            public static readonly string Exploited = "悪用";
            public static readonly string LatestReleaseExploitability = "最新のソフトウェア リリース";
            public static readonly string OlderReleaseExploitability = "過去のソフトウェア リリース";
            public static readonly string DenialOfService = "サービス拒否";
            public static readonly string VectorString = "CVSS";
            public static readonly string BaseScore = "基本値";
            public static readonly string TemporalScore = "現状値";
            public static readonly string EaseOfAttack = "攻撃しやすさ";
            public static readonly string Remarks = "備考";
        }

        public static class ProductName
        {
            public static readonly string Win_2008_32Bit_SP2 = "Windows Server 2008 for 32-bit Systems Service Pack 2";
            public static readonly string Win_2012_R2_SeverCore = "Windows Server 2012 R2 (Server Core installation)";
            public static readonly string Win_2012_R2 = "Windows Server 2012 R2";
            public static readonly string Win_2016_ServerCore = "Windows Server 2016  (Server Core installation)";
            public static readonly string Win_2016 = "Windows Server 2016";
            public static readonly string MS_NET_Framework_4_x = "Microsoft .NET Framework 4";
            public static readonly string MS_SQL_Server_2014_x = "Microsoft SQL Server 2014";
            public static readonly string IE_11 = "Internet Explorer 11";
        }
    }
}
