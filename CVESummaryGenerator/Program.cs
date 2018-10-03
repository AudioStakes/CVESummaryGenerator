using System;
using System.IO;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
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
            // まとめ作成対象CVE一覧を取得
            var targetCVEs = GetTargetCVEs();

            // まとめ対象CVEを分割してリスト化
            string[] targetCVElist = targetCVEs.Split(' ');

            // 対象製品リストを取得
            var targetProducts = GetTargetProducts();

            // まとめデータを格納するテーブルを作成
            DataSet dataSet = new DataSet(); // 表形式のデータをメモリ領域へ格納するクラス
            DataTable table = new DataTable("SummaryTable"); // 表形式のデータを扱う

            // テーブルにカラム名の追加
            table.Columns.Add(Constants.ColumnName.CveNumber);
            table.Columns.Add(Constants.ColumnName.CveTitle);
            table.Columns.Add(Constants.ColumnName.Description);
            table.Columns.Add(Constants.ColumnName.Severity);
            table.Columns.Add(Constants.ColumnName.PubliclyDisclosed);
            table.Columns.Add(Constants.ColumnName.Exploited);
            table.Columns.Add(Constants.ColumnName.LatestReleaseExploitability);
            table.Columns.Add(Constants.ColumnName.OlderReleaseExploitability);
            table.Columns.Add(Constants.ColumnName.DenialOfService);
            table.Columns.Add(Constants.ColumnName.VectorString);
            table.Columns.Add(Constants.ColumnName.BaseScore, Type.GetType("System.Double"));
            table.Columns.Add(Constants.ColumnName.TemporalScore, Type.GetType("System.Double"));
            foreach (var targetProduct in targetProducts)
            {
                table.Columns.Add(targetProduct);
            }
            table.Columns.Add(Constants.ColumnName.Remarks);

            // DataSetにDataTableを追加
            dataSet.Tables.Add(table);

            foreach (var cve in targetCVElist)
            {
                // CVEに対応する行を作成
                DataRow workRow = table.NewRow();

                // CVENumberを格納
                workRow[Constants.ColumnName.CveNumber] = cve;
                Console.WriteLine(cve);

                // 正規表現とマッチするかチェックする
                if (!Regex.IsMatch(cve, @"^(CVE-20[0-9][0-9]-\d{4}$|^ADV\d{6}$)"))
                {
                    workRow[Constants.ColumnName.Remarks] = "CVEの正規表現と一致しません";
                    table.Rows.Add(workRow);
                    continue;
                }

                //json形式CVE情報を取得する
                var JsonCveInfo = GetJsonCveInfo(cve);
                if (String.IsNullOrEmpty(JsonCveInfo))
                {
                    // ＴＯＤＯ：エラーをそのまま出力できるようにメソッドを変更する
                    workRow[Constants.ColumnName.Remarks] = "404 Not Found";
                    table.Rows.Add(workRow);
                    continue;
                }

                // JSONを.NETのクラスにデシリアライズ
                SecurityGuidance sg = JsonConvert.DeserializeObject<SecurityGuidance>(JsonCveInfo);

                // TODO：「サービス拒否」の項目はjsonにないのか確認

                // 共通項目のデータを格納する
                SetCommonCveValueToWorkRow(workRow, sg);

                // 対象とする製品のデータを抽出する
                var affectedTargetProducts = sg.AffectedProducts.Where(n => 
                    n.Name == Constants.ProductName.Win_2008_32Bit_SP2
                    || n.Name == Constants.ProductName.Win_2012_R2_SeverCore
                    || n.Name == Constants.ProductName.Win_2016_ServerCore
                    );

                // targetProductsの有無を判別し、なければ処理終了
                if (!affectedTargetProducts.Any())
                {
                    workRow[Constants.ColumnName.Remarks] = "CVEの対象製品の中に目的の製品が含まれていません";
                    table.Rows.Add(workRow);
                    continue;
                }

                // まとめデータ格納用クラスの初期化
                AffectedProduct summaryOfTargetProducts = new AffectedProduct();

                // ループに用いる変数を初期化
                bool isFirst = true;

                // 対象製品を有無を表すハッシュテーブルを作成する
                Hashtable TableRepresentingPresenceOfTargetProduct = CreateTableRepresentingPresenceOfTargetProduct(targetProducts);

                // 対象製品データのうち値が同じ項目は一つにまとめる
                foreach (var affectedTargetProduct in affectedTargetProducts)
                {
                    // ＣＶＥの影響対象製品と一致する目的製品を確認する
                    CheckIfEqualToProductName(affectedTargetProduct.Name, TableRepresentingPresenceOfTargetProduct);

                    if (isFirst)
                    {
                        // １番目のデータは丸ごと代入する
                        summaryOfTargetProducts = affectedTargetProduct;
                        isFirst = false;
                        continue;
                    }
                    else
                    {
                        // ２番目以降のデータは１番目と一致するか確認する
                        CheckIfEqualToAssignedData(summaryOfTargetProducts, affectedTargetProduct);
                    }
                }

                // tableへのデータ追加用文字列を作成
                var LatestRelease = sg.ExploitabilityAssessment.LatestReleaseExploitability.Id.ToString() + "-" + sg.ExploitabilityAssessment.LatestReleaseExploitability.Name; // 最新のソフトウェア リリース
                var OlderRelease = sg.ExploitabilityAssessment.OlderReleaseExploitability.Id.ToString() + "-" + sg.ExploitabilityAssessment.OlderReleaseExploitability.Name; // 過去のソフトウェア リリース

                // 対象製品データのまとめを格納する
                workRow[Constants.ColumnName.LatestReleaseExploitability] = LatestRelease;
                workRow[Constants.ColumnName.OlderReleaseExploitability] = OlderRelease;
                workRow[Constants.ColumnName.VectorString] = summaryOfTargetProducts.VectorString;
                workRow[Constants.ColumnName.BaseScore] = summaryOfTargetProducts.BaseScore;
                workRow[Constants.ColumnName.TemporalScore] = summaryOfTargetProducts.TemporalScore;
                workRow[Constants.ColumnName.Severity] = summaryOfTargetProducts.Severity;
                foreach (string targetProductName in TableRepresentingPresenceOfTargetProduct.Keys)
                {
                    workRow[targetProductName] = TableRepresentingPresenceOfTargetProduct[targetProductName];
                }

                // Rows.Addメソッドを使ってデータを追加
                table.Rows.Add(workRow);
            }

            Console.WriteLine("tableの中身を表示");
            foreach (DataRow Row in table.Rows)
            {
                for (int i = 0; i < Row.ItemArray.Length; i++)
                {
                    Console.WriteLine(Row[i].ToString() + "|");
                }
            }

            // ＣＳＶファイル保存先の完全パスを取得
            string csvPath = GetFullPathWithCurrentDirectoryAndCurrentTimeAsCSVFileName();

            // CSVコンバーターを呼び出す
            DatatableToCSVConverter csv = new DatatableToCSVConverter();

            // DataTableをCSVで保存する
            csv.ConvertDataTableToCsv(table, csvPath, true);

            Console.ReadLine();
        }

        private static void CheckIfEqualToAssignedData(AffectedProduct summaryOfTargetProducts, AffectedProduct affectedTargetProduct)
        {
            if (!summaryOfTargetProducts.VectorString.Equals(affectedTargetProduct.VectorString))
            {
                summaryOfTargetProducts.VectorString = default(string);
                Console.WriteLine("対象製品のVectorStringに一致しない値があります");
            }

            if (!summaryOfTargetProducts.BaseScore.Equals(affectedTargetProduct.BaseScore))
            {
                summaryOfTargetProducts.BaseScore = default(double);
                Console.WriteLine("対象製品のBaseScoreに一致しない値があります");
            }

            if (!summaryOfTargetProducts.TemporalScore.Equals(affectedTargetProduct.TemporalScore))
            {
                summaryOfTargetProducts.TemporalScore = default(double);
                Console.WriteLine("対象製品のTemporalScoreに一致しない値があります");
            }

            if (!summaryOfTargetProducts.Severity.Equals(affectedTargetProduct.Severity))
            {
                summaryOfTargetProducts.Severity = default(string);
                Console.WriteLine("対象製品のSeverityの中に一致しないものがあります");
            }
        }

        private static void CheckIfEqualToProductName(string affectedTargetProductName, Hashtable tableRepresentingPresenceOfTargetProduct)
        {
            ArrayList targetProductNameList = new ArrayList(tableRepresentingPresenceOfTargetProduct.Keys);
            foreach (string targetProductName in targetProductNameList)
            {
                if (affectedTargetProductName == targetProductName)
                {
                    tableRepresentingPresenceOfTargetProduct[targetProductName] = "○";
                }
            }
        }

        private static Hashtable CreateTableRepresentingPresenceOfTargetProduct(List<string> targetProducts)
        {
            Hashtable TableRepresentingPresenceOfTargetProduct = new Hashtable();
            foreach (var targetProduct in targetProducts)
            {
                TableRepresentingPresenceOfTargetProduct.Add(targetProduct, "x");
            }
            return TableRepresentingPresenceOfTargetProduct;
        }

        private static void SetCommonCveValueToWorkRow(DataRow workRow, SecurityGuidance sg)
        {
            workRow[Constants.ColumnName.CveTitle] = sg.CveTitle;
            workRow[Constants.ColumnName.Description] = sg.Description.Replace("\n", "");
            workRow[Constants.ColumnName.PubliclyDisclosed] = sg.PubliclyDisclosed;
            workRow[Constants.ColumnName.Exploited] = sg.Exploited;
        }

        private static string GetJsonCveInfo(string cve)
        {
            using (var wc = new WebClient()){
                wc.Encoding = Encoding.UTF8;
                try
                {
                    // APIからjson形式の文字列を取得
                    return wc.DownloadString(@"https://portal.msrc.microsoft.com/api/security-guidance/ja-JP/CVE/" + cve);
                }
                catch (WebException)
                {
                    return null;
                }
            }
        }

        private static List<string> GetTargetProducts()
        {
            return new List<string>(){
                Constants.ProductName.Win_2008_32Bit_SP2,
                Constants.ProductName.Win_2012_R2_SeverCore,
                Constants.ProductName.Win_2016_ServerCore,
            };
        }

        private static string GetFullPathWithCurrentDirectoryAndCurrentTimeAsCSVFileName()
        {
            // カレントディレクトリのパスを取得する
            string CurrentDir = Directory.GetCurrentDirectory();

            // ファイル名を現在時刻を「西暦月日時分秒」形式で取得する
            string now = DateTime.Now.ToString("yyyyMMddHHmmss");

            string fname = now + ".csv";

            // 保存先のCSVファイルのパスを組み立てる
            return Path.Combine(CurrentDir, fname);
        }

        private static string GetTargetCVEs()
        {
            return @"CVE-2018-8392 CVE-2018-8393 ADV180022 CVE-2018-0965 CVE-2018-8271 CVE-2018-8332 CVE-2018-8335 CVE-2018-8336 CVE-2018-8410 CVE-2018-8419 CVE-2018-8420 CVE-2018-8421 CVE-2018-8424 CVE-2018-8433 CVE-2018-8434 CVE-2018-8435 CVE-2018-8438 CVE-2018-8439 CVE-2018-8440 CVE-2018-8442 CVE-2018-8443 CVE-2018-8444 CVE-2018-8446 CVE-2018-8449 CVE-2018-8455 CVE-2018-8462 CVE-2018-8468 CVE-2018-8475";
            //return @"CVE-2018-8308 CVE-2018-83080 CVE-2018-8176 CVE-2018-8311 ADV113456 正規表現と一致しない";
        }
    }
}
