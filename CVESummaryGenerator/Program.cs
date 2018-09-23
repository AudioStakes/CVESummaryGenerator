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
            var targetCVElist = new List<string>(){
                "CVE-2018-8308",
                "CVE-2018-8309",
                "CVE-2018-8176",
                "CVE-2018-8311",
                "ADV113456",
                "正規表現と一致しない"
            };

            // 対象製品名を変数に設定
            string WIN2008 = "Windows Server 2008 for 32-bit Systems Service Pack 2";
            string WIN2012 = "Windows Server 2012 R2 (Server Core installation)";
            string WIN2016 = "Windows Server 2016  (Server Core installation)";

            var targetOSs = new List<string>(){
                "Windows Server 2008 for 32-bit Systems Service Pack 2",
                "Windows Server 2012 R2 (Server Core installation)",
                "Windows Server 2016  (Server Core installation)"
            };

            // まとめデータを格納するテーブルを作成
            DataSet dataSet = new DataSet(); // 表形式のデータをメモリ領域へ格納するクラス
            DataTable table = new DataTable("SummaryTable"); // 表形式のデータを扱う

            // カラム名
            string CveNumber = "CVE";
            string CveTitle = "概要";
            string Description = "詳細";
            string PubliclyDisclosed = "一般に公開";
            string Exploited = "悪用";
            string LatestReleaseExploitability = "最新のソフトウェア リリース";
            string OlderReleaseExploitability = "過去のソフトウェア リリース";
            string VectorString = "CVSS";
            string BaseScore = "BaseScore";
            string TemporalScore = "TemporalScore";
            string Severity = "深刻度";
            string Remarks = "備考";

            // テーブルにカラム名の追加
            table.Columns.Add(CveNumber);
            table.Columns.Add(CveTitle);
            table.Columns.Add(Description);
            table.Columns.Add(PubliclyDisclosed);
            table.Columns.Add(Exploited);
            table.Columns.Add(LatestReleaseExploitability);
            table.Columns.Add(OlderReleaseExploitability);
            table.Columns.Add(VectorString);
            table.Columns.Add(BaseScore, Type.GetType("System.Double"));
            table.Columns.Add(TemporalScore, Type.GetType("System.Double"));
            table.Columns.Add(Severity);
            foreach (var product in targetOSs)
            {
                table.Columns.Add(product);
            }
            table.Columns.Add(Remarks);

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
                    workRow[CveNumber] = cve;
                    Console.WriteLine(cve);

                    if (!Regex.IsMatch(cve, @"(CVE-20[0-9][0-9]-\d{4}|ADV\d{6})"))
                    {
                        workRow[Remarks] = "CVEの正規表現と一致しません";
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
                        workRow[Remarks] = ex.Message;
                        table.Rows.Add(workRow);
                        continue;
                    }
                    // ダウンロードしたjson文字列を出力
                    Console.WriteLine(jsonString);

                    // JSONを.NETのクラスにデシリアライズ
                    SecurityGuidance sg = JsonConvert.DeserializeObject<SecurityGuidance>(jsonString);

                    // TODO：「サービス拒否」の項目はjsonにないのか確認

                    // 共通項目のデータを格納する
                    workRow[CveTitle] = sg.CveTitle;
                    workRow[Description] = sg.Description.Replace("\n", "");
                    workRow[PubliclyDisclosed] = sg.PubliclyDisclosed;
                    workRow[Exploited] = sg.Exploited;

                    // 対象とする製品のデータを抽出する
                    var targetProducts = sg.AffectedProducts.Where(n => n.Name == WIN2008 || n.Name == WIN2012 || n.Name == WIN2016);

                    // targetProductsの有無を判別し、なければ処理終了
                    if (!targetProducts.Any())
                    {
                        workRow[Remarks] = "CVEの対象製品の中に目的の製品が含まれていません";
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
                    var LatestRelease = sg.ExploitabilityAssessment.LatestReleaseExploitability.Id.ToString() + "-" + sg.ExploitabilityAssessment.LatestReleaseExploitability.Name; // 最新のソフトウェア リリース
                    var OlderRelease = sg.ExploitabilityAssessment.OlderReleaseExploitability.Id.ToString() + "-" + sg.ExploitabilityAssessment.OlderReleaseExploitability.Name; // 過去のソフトウェア リリース

                    // 対象製品データのまとめを格納する
                    workRow[LatestReleaseExploitability] = LatestRelease;
                    workRow[OlderReleaseExploitability] = OlderRelease;
                    workRow[VectorString] = summaryOfTargetProducts.VectorString;
                    workRow[BaseScore] = summaryOfTargetProducts.BaseScore;
                    workRow[TemporalScore] = summaryOfTargetProducts.TemporalScore;
                    workRow[Severity] = summaryOfTargetProducts.Severity;
                    workRow[WIN2008] = containsWIN2008;
                    workRow[WIN2012] = containsWIN2012;
                    workRow[WIN2016] = containsWIN2016;

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

            // CSVコンバーターを呼び出す
            DatatableToCSVConverter csv = new DatatableToCSVConverter();

            // カレントディレクトリのパスを取得する
            string CurrentDir = Directory.GetCurrentDirectory();

            // ファイル名を現在時刻を「西暦月日時分秒」形式で取得する
            string now = DateTime.Now.ToString("yyyyMMddHHmmss");

            string fname = now + ".csv";

            // 保存先のCSVファイルのパスを組み立てる
            string csvPath = Path.Combine(CurrentDir, fname);

            // DataTableをCSVで保存する
            csv.ConvertDataTableToCsv(table, csvPath, true);

            Console.ReadLine();
        }
    }
}
