using System;
using System.IO;
using System.Linq;
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

            var targetOSs = new List<string>(){
                Constants.ProductName.Win_2008_32Bit_SP2,
                Constants.ProductName.Win_2012_R2_SeverCore,
                Constants.ProductName.Win_2016_ServerCore
            };

            // まとめデータを格納するテーブルを作成
            DataSet dataSet = new DataSet(); // 表形式のデータをメモリ領域へ格納するクラス
            DataTable table = new DataTable("SummaryTable"); // 表形式のデータを扱う

            // テーブルにカラム名の追加
            table.Columns.Add(Constants.ColumnName.CveNumber);
            table.Columns.Add(Constants.ColumnName.CveTitle);
            table.Columns.Add(Constants.ColumnName.Description);
            table.Columns.Add(Constants.ColumnName.PubliclyDisclosed);
            table.Columns.Add(Constants.ColumnName.Exploited);
            table.Columns.Add(Constants.ColumnName.LatestReleaseExploitability);
            table.Columns.Add(Constants.ColumnName.OlderReleaseExploitability);
            table.Columns.Add(Constants.ColumnName.VectorString);
            table.Columns.Add(Constants.ColumnName.BaseScore, Type.GetType("System.Double"));
            table.Columns.Add(Constants.ColumnName.TemporalScore, Type.GetType("System.Double"));
            table.Columns.Add(Constants.ColumnName.Severity);
            foreach (var product in targetOSs)
            {
                table.Columns.Add(product);
            }
            table.Columns.Add(Constants.ColumnName.Remarks);

            // DataSetにDataTableを追加
            dataSet.Tables.Add(table);

            // WebClientを初期化
            using(var wc = new WebClient())
            {
                wc.Encoding = Encoding.UTF8;

                foreach (var cve in targetCVElist)
                {

                    // CVEに対応する行を作成
                    DataRow workRow = table.NewRow();

                    // CVENumberを格納
                    workRow[Constants.ColumnName.CveNumber] = cve;
                    Console.WriteLine(cve);

                    if (!Regex.IsMatch(cve, @"^(CVE-20[0-9][0-9]-\d{4}$|^ADV\d{6}$)"))
                    {
                        workRow[Constants.ColumnName.Remarks] = "CVEの正規表現と一致しません";
                        table.Rows.Add(workRow);
                        continue;
                    }

                    string jsonString = "";
                    try
                    {
                        // APIからjson形式の文字列を取得
                        jsonString = wc.DownloadString(@"https://portal.msrc.microsoft.com/api/security-guidance/ja-JP/CVE/" + cve);
                    }
                    catch (WebException ex)
                    {
                        Console.WriteLine(ex.Message);
                        workRow[Constants.ColumnName.Remarks] = ex.Message;
                        table.Rows.Add(workRow);
                        continue;
                    }
                    // ダウンロードしたjson文字列を出力
                    Console.WriteLine(jsonString);

                    // JSONを.NETのクラスにデシリアライズ
                    SecurityGuidance sg = JsonConvert.DeserializeObject<SecurityGuidance>(jsonString);

                    // TODO：「サービス拒否」の項目はjsonにないのか確認

                    // 共通項目のデータを格納する
                    workRow[Constants.ColumnName.CveTitle] = sg.CveTitle;
                    workRow[Constants.ColumnName.Description] = sg.Description.Replace("\n", "");
                    workRow[Constants.ColumnName.PubliclyDisclosed] = sg.PubliclyDisclosed;
                    workRow[Constants.ColumnName.Exploited] = sg.Exploited;

                    // 対象とする製品のデータを抽出する
                    var targetProducts = sg.AffectedProducts.Where(n => n.Name == Constants.ProductName.Win_2008_32Bit_SP2
                                                                   || n.Name == Constants.ProductName.Win_2012_R2_SeverCore
                                                                   || n.Name == Constants.ProductName.Win_2016_ServerCore
                                                                  );

                    // targetProductsの有無を判別し、なければ処理終了
                    if (!targetProducts.Any())
                    {
                        workRow[Constants.ColumnName.Remarks] = "CVEの対象製品の中に目的の製品が含まれていません";
                        table.Rows.Add(workRow);
                        continue;
                    }

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
                        if (product.Name == Constants.ProductName.Win_2008_32Bit_SP2) { containsWIN2008 = "○"; }
                        if (product.Name == Constants.ProductName.Win_2012_R2_SeverCore) { containsWIN2012 = "○"; }
                        if (product.Name == Constants.ProductName.Win_2016_ServerCore) { containsWIN2016 = "○"; }

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
                    var LatestRelease = sg.ExploitabilityAssessment.LatestReleaseExploitability.Id.ToString() + "-" + sg.ExploitabilityAssessment.LatestReleaseExploitability.Name; // 最新のソフトウェア リリース
                    var OlderRelease = sg.ExploitabilityAssessment.OlderReleaseExploitability.Id.ToString() + "-" + sg.ExploitabilityAssessment.OlderReleaseExploitability.Name; // 過去のソフトウェア リリース

                    // 対象製品データのまとめを格納する
                    workRow[Constants.ColumnName.LatestReleaseExploitability] = LatestRelease;
                    workRow[Constants.ColumnName.OlderReleaseExploitability] = OlderRelease;
                    workRow[Constants.ColumnName.VectorString] = summaryOfTargetProducts.VectorString;
                    workRow[Constants.ColumnName.BaseScore] = summaryOfTargetProducts.BaseScore;
                    workRow[Constants.ColumnName.TemporalScore] = summaryOfTargetProducts.TemporalScore;
                    workRow[Constants.ColumnName.Severity] = summaryOfTargetProducts.Severity;
                    workRow[Constants.ProductName.Win_2008_32Bit_SP2] = containsWIN2008;
                    workRow[Constants.ProductName.Win_2012_R2_SeverCore] = containsWIN2012;
                    workRow[Constants.ProductName.Win_2016_ServerCore] = containsWIN2016;

                    // Rows.Addメソッドを使ってデータを追加
                    table.Rows.Add(workRow);
                }
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
            return @"CVE-2018-8308 CVE-2018-83080 CVE-2018-8176 CVE-2018-8311 ADV113456 正規表現と一致しない";
        }
    }
}
