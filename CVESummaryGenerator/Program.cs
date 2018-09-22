using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Data;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace CVESummaryGenerator
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            string WIN2008 = "Windows Server 2008 for 32-bit Systems Service Pack 2";
            string WIN2012 = "Windows Server 2012 R2 (Server Core installation)";
            string WIN2016 = "Windows Server 2016  (Server Core installation)";
            var wc = new WebClient();
            wc.Encoding = Encoding.UTF8;

            // TODO:取得するCVE一覧を取得

            // TODO:CVE一覧から取得するCVEを一つずつ取得
            var cve = "CVE-2018-8308";

            // TODO:正規表現で正しいCVEかチェックする
            // (CVE - 20[0 - 9][0 - 9] -\d{ 4}|ADV\d{ 6})

            if (Regex.IsMatch(cve, @"(CVE-20[0-9][0-9]-\d{4}|ADV\d{6})"))
            {
                Console.WriteLine("正規表現と一致します");
            }
            else
            {
                Console.WriteLine("一致しません");
            }

            // APIからjson形式の文字列を取得
            var jsonString = wc.DownloadString(@"https://portal.msrc.microsoft.com/api/security-guidance/ja-JP/CVE/" + cve);

            // ダウンロードしたjson文字列を出力
            Console.WriteLine(jsonString);

            // JSONを.NETのクラスにデシリアライズ
            SecurityGuidance sg = JsonConvert.DeserializeObject<SecurityGuidance>(jsonString);

            // まとめデータを格納するテーブルを作成
            DataSet dataSet = new DataSet(); // 表形式のデータをメモリ領域へ格納するクラス
            DataTable table = new DataTable("SummaryTable"); // 表形式のデータを扱う

            // カラム名の追加
            table.Columns.Add("CVE");
            table.Columns.Add("概要");
            table.Columns.Add("詳細");
            table.Columns.Add("一般に公開");
            table.Columns.Add("悪用");
            table.Columns.Add("最新のソフトウェア リリース");
            table.Columns.Add("過去のソフトウェア リリース");
            table.Columns.Add("VectorString");
            table.Columns.Add("BaseScore", Type.GetType("System.Double"));
            table.Columns.Add("TemporalScore", Type.GetType("System.Double"));
            table.Columns.Add("Severity");
            table.Columns.Add(WIN2008);
            table.Columns.Add(WIN2012);
            table.Columns.Add(WIN2016);

            // DataSetにDataTableを追加
            dataSet.Tables.Add(table);

            // TODO：「サービス拒否」の項目はjsonにないのか確認

            // 対象とする製品のデータを抽出する
            var targetProducts = sg.AffectedProducts.Where(n => n.Name == WIN2008 || n.Name == WIN2012 || n.Name == WIN2016);

            // まとめデータ格納用クラスの初期化
            AffectedProduct summaryOfTargetProducts = new AffectedProduct();

            // ループに用いる変数を初期化
            bool isFirst = true;
            string containsWIN2008 = "☓";
            string containsWIN2012 = "☓";
            string containsWIN2016 = "☓";

            // 対象製品データのうち値が同じ項目は一つにまとめる
            foreach (var product in targetProducts)
            {
                // ＣＶＥの対象製品が以下の製品のどれに該当するかチェックする
                if (product.Name == WIN2008) { containsWIN2008 = "○"; }
                if (product.Name == WIN2012) { containsWIN2012 = "○"; }
                if (product.Name == WIN2016) { containsWIN2016 = "○"; }

                if (isFirst)
                {
                    summaryOfTargetProducts = product;
                    isFirst = false;
                    continue;
                }

                if (!summaryOfTargetProducts.VectorString.Equals(product.VectorString))
                {
                    summaryOfTargetProducts.VectorString = "vectorStringの中に一致しないものがあります";
                    Console.WriteLine(summaryOfTargetProducts.VectorString);
                }
                
                if (!summaryOfTargetProducts.BaseScore.Equals(product.BaseScore))
                {
                    summaryOfTargetProducts.BaseScore = 0;
                    Console.WriteLine("baseScoreの中に一致しないものがあります");
                }

                if (!summaryOfTargetProducts.TemporalScore.Equals(product.TemporalScore))
                {
                    summaryOfTargetProducts.TemporalScore = 0;
                    Console.WriteLine("temporalScoreの中に一致しないものがあります");
                }

                if (!summaryOfTargetProducts.Severity.Equals(product.Severity))
                {
                    summaryOfTargetProducts.Severity = "severityの中に一致しないものがあります";
                    Console.WriteLine("severityの中に一致しないものがあります");
                }
            }

            // tableへのデータ追加用文字列を作成
            var LatestReleaseExploitability = sg.ExploitabilityAssessment.LatestReleaseExploitability.Id.ToString() + "-" + sg.ExploitabilityAssessment.LatestReleaseExploitability.Name; // 最新のソフトウェア リリース
            var OlderReleaseExploitability = sg.ExploitabilityAssessment.OlderReleaseExploitability.Id.ToString() + "-" + sg.ExploitabilityAssessment.OlderReleaseExploitability.Name; // 過去のソフトウェア リリース

            // Rows.Addメソッドを使ってデータを追加
            table.Rows.Add(cve
                , sg.CveTitle
                , sg.Description.Replace("\n", "")
                , sg.PubliclyDisclosed
                , sg.Exploited
                , LatestReleaseExploitability
                , OlderReleaseExploitability
                , summaryOfTargetProducts.VectorString
                , summaryOfTargetProducts.BaseScore
                , summaryOfTargetProducts.TemporalScore
                , summaryOfTargetProducts.Severity
                , containsWIN2008
                , containsWIN2012
                , containsWIN2016);

            Console.WriteLine("tableの中身を表示");
            foreach (DataRow Row in table.Rows)
            {
                for (int i = 0; i < Row.ItemArray.Length; i++)
                {
                    Console.WriteLine(Row[i].ToString() + "|");
                }
            }

            // CSVコンバーターを呼び出す
            DatatableToCSVConverter csv = new DatatableToCSVConverter();

            // カレントディレクトリのパスを取得する
            string CurrentDir = Directory.GetCurrentDirectory();

            // ファイル名を現在時刻を「西暦月日時分秒」形式で取得する
            string now = DateTime.Now.ToString("yyyyMMddHHmmss");

            // 保存先のCSVファイルのパス
            string csvPath = CurrentDir + "/" + now + ".csv";

            // DataTableをCSVで保存する
            csv.ConvertDataTableToCsv(table, csvPath, true);

            Console.ReadLine();

        }
    }
}
