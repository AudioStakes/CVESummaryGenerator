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
using System.Windows.Forms;
using System.Threading;

// TODO: ADV系（ADV180028 ADV990001）もプログラムが動くようにする
// TODO: IE, Edgeを対象製品としているCVEもプログラムが動くようにする
// TODO: （ほぼ↑と同意）2018/11のCVE一覧のCVEで動作するようにする

namespace CVESummaryGenerator
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            //Application.Run(new CveSummaryGeneratorForm());

            // まとめ作成対象CVE一覧を取得
            var targetCVEs = GetTargetCVEs();

            // まとめ対象CVEを分割してリスト化
            string[] targetCVElist = targetCVEs.Split(' ');

            // 対象製品リストを取得
            var targetProducts = GetTargetProducts();

            // メモリ上のデータベースを作成
            DataSet dataSet = new DataSet();

            // まとめデータを扱うテーブルを作成
            DataTable summaryTable = new DataTable("SummaryTable");

            // まとめテーブルにカラム名の追加
            SetColumnsToSummaryTable(targetProducts, summaryTable);

            // ＤＢにまとめテーブルを追加
            dataSet.Tables.Add(summaryTable);

            // 影響対象製品のデータを扱うテーブルを作成
            DataTable affectedTargetProductsTable = new DataTable("AffectedTargetProducts");

            // 影響対象製品のデータを扱うテーブルにカラム名を設定
            SetColumnsToAffectedTargetProductsTable(affectedTargetProductsTable);

            foreach (var cve in targetCVElist)
            {
                // サーバアクセスの間隔を1秒以上空けるようにする
                Thread.Sleep(1000);

                // CVEに対応する行を作成
                DataRow workRow = summaryTable.NewRow();

                // CVENumberを格納
                workRow[Constants.SummaryTableColumn.CveNumber] = cve;
                Console.WriteLine(cve);

                // 正規表現とマッチするかチェックする
                if (!Regex.IsMatch(cve, @"^(CVE-20[0-9][0-9]-\d{4}$|^ADV\d{6}$)"))
                {
                    workRow[Constants.SummaryTableColumn.Remarks] = "CVEの正規表現と一致しません";
                    summaryTable.Rows.Add(workRow);
                    continue;
                }

                //json形式CVE情報を取得する
                var JsonCveInfo = GetJsonCveInfo(cve);
                if (String.IsNullOrEmpty(JsonCveInfo))
                {
                    // ＴＯＤＯ：エラーをそのまま出力できるようにメソッドを変更する
                    workRow[Constants.SummaryTableColumn.Remarks] = "404 Not Found";
                    summaryTable.Rows.Add(workRow);
                    continue;
                }

                // supply settings to JsonConvert.DeserializeObject to handle null values
                var settings = new JsonSerializerSettings
                {
                    NullValueHandling = NullValueHandling.Ignore,
                    MissingMemberHandling = MissingMemberHandling.Ignore
                };
                // JSONを.NETのクラスにデシリアライズ
                SecurityGuidance sg = JsonConvert.DeserializeObject<SecurityGuidance>(JsonCveInfo, settings);

                // 共通項目のデータを格納する
                SetCommonCveValueToWorkRow(workRow, sg);

                // 対象とする製品のデータを抽出する
                var affectedTargetProducts = sg.AffectedProducts.Where(n =>
                    n.Name == Constants.ProductName.Win_2012_R2_SeverCore
                    || n.Name == Constants.ProductName.Win_2012_R2
                    || n.Name == Constants.ProductName.Win_2016_ServerCore
                    || n.Name == Constants.ProductName.Win_2016
                    || n.Name.Contains(Constants.ProductName.MS_NET_Framework_4_x)
                    || n.Name.Contains(Constants.ProductName.MS_SQL_Server_2014_x)
                    || n.Name == Constants.ProductName.IE_11
                    );

                // targetProductsの有無を判別し、なければ処理終了
                if (!affectedTargetProducts.Any())
                {
                    workRow[Constants.SummaryTableColumn.Remarks] = "CVEの対象製品の中に目的の製品が含まれていません";
                    summaryTable.Rows.Add(workRow);
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
                    //　Tableに新しい行を作成してaffectedTargetProduct情報をセット
                    SetAffectedTargetProductsRow(affectedTargetProductsTable, affectedTargetProduct, cve);

                    // ＣＶＥの影響対象製品と一致する目的製品を確認する
                    CheckIfContainToProductName(affectedTargetProduct.Name, TableRepresentingPresenceOfTargetProduct);

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

                // ループで作成した対象製品データのまとめを格納する
                SetSummaryOfTargetProductsToWorkRow(workRow, summaryOfTargetProducts, TableRepresentingPresenceOfTargetProduct);

                // CVSSからCVEの攻撃のしやすさを判別する
                CheckEaseOfAttack(workRow);

                // Rows.Addメソッドを使ってデータを追加
                summaryTable.Rows.Add(workRow);
            }

            // TODO:CVEの脅威レベル（自作）で優先度順に並べられるようにする

            // ＣＳＶファイル保存先の完全パスを取得
            string csvPath = GetFullPathWithCurrentDirectoryAndCurrentTimeAsCSVFileName();
            Console.WriteLine(csvPath);

            // CSVコンバーターを呼び出す
            DatatableToCSVConverter csv = new DatatableToCSVConverter();

            // DistinctなダウンロードＵＲＬを取得する
            // TODO:ADV系の記事を集計から除去する or ADV系であることがわかるようにする
            DataTable distinctUrlForEachName = affectedTargetProductsTable.DefaultView.ToTable(true, "Name", "ArticleUrl1", "DownloadTitle1", "DownloadUrl1", "ArticleUrl2", "DownloadTitle2", "DownloadUrl2", "ArticleUrl3", "DownloadTitle3", "DownloadUrl3", "ArticleUrl4", "DownloadTitle4", "DownloadUrl4");

            // DataTableをCSVで保存する
            csv.ConvertDataTableToCsv(summaryTable, csvPath, true);
            csv.ConvertDataTableToCsv(affectedTargetProductsTable, csvPath + "_affectedTargetProducts.csv", true);
            csv.ConvertDataTableToCsv(distinctUrlForEachName, csvPath + "_distinctUrlForEachName.csv", true);

            Console.ReadLine();
        }

        private static void SetAffectedTargetProductsRow(DataTable affectedTargetProductsTable, AffectedProduct affectedTargetProduct, string cve)
        {
            // affectedTargetProductに対応する行を作成
            DataRow affectedTargetProductRow = affectedTargetProductsTable.NewRow();

            // CVENumberを格納
            affectedTargetProductRow["CveNumber"] = cve;

            // affectedTargetProductの値を行へセット
            SetAffectedTargetProductValuesToRow(affectedTargetProduct, affectedTargetProductRow);

            // Rows.Addメソッドを使ってデータを追加
            affectedTargetProductsTable.Rows.Add(affectedTargetProductRow);
        }

        private static void CheckEaseOfAttack(DataRow workRow)
        {
            if (String.IsNullOrEmpty(workRow[Constants.SummaryTableColumn.VectorString] as string))
            {
                workRow[Constants.SummaryTableColumn.EaseOfAttack] = "";
            }
            else
            {
                string CVSS = workRow[Constants.SummaryTableColumn.VectorString] as string;
                bool IS_AV_N = CVSS.Contains("AV:N");
                bool IS_AC_L = CVSS.Contains("AC:L");
                bool IS_PR_N = CVSS.Contains("PR:N");
                bool IS_UI_N = CVSS.Contains("UI:N");

                if (IS_AV_N && IS_AC_L && IS_PR_N && IS_UI_N)
                {
                    workRow[Constants.SummaryTableColumn.EaseOfAttack] = "★★★危険。詳細を要チェック★★★";
                }

                if (!IS_AV_N)
                {
                    workRow[Constants.SummaryTableColumn.EaseOfAttack] += "(-)攻撃元区分はネットワークではない" + Environment.NewLine;
                }
                if (!IS_AC_L)
                {
                    workRow[Constants.SummaryTableColumn.EaseOfAttack] += "(-)攻撃条件の複雑さが高い" + Environment.NewLine;
                }
                if (!IS_PR_N)
                {
                    workRow[Constants.SummaryTableColumn.EaseOfAttack] += "(-)特権レベルが必要とされている" + Environment.NewLine;
                }
                if (!IS_UI_N)
                {
                    workRow[Constants.SummaryTableColumn.EaseOfAttack] += "(-)ユーザ関与を必要とする" + Environment.NewLine;
                }
            }
        }

        private static void OutputValuesOfTheSummaryTable(DataTable summaryTable)
        {
            foreach (DataRow Row in summaryTable.Rows)
            {
                for (int i = 0; i < Row.ItemArray.Length; i++)
                {
                    Console.WriteLine(Row[i]);
                }
            }
        }

        private static void SetSummaryOfTargetProductsToWorkRow(DataRow workRow, AffectedProduct summaryOfTargetProducts, Hashtable tableRepresentingPresenceOfTargetProduct)
        {
            workRow[Constants.SummaryTableColumn.VectorString] = summaryOfTargetProducts.VectorString;
            workRow[Constants.SummaryTableColumn.BaseScore] = summaryOfTargetProducts.BaseScore;
            workRow[Constants.SummaryTableColumn.TemporalScore] = summaryOfTargetProducts.TemporalScore;

            // 深刻度が「緊急」の場合は攻撃しやすさ列に(+)として設定
            workRow[Constants.SummaryTableColumn.Severity] = summaryOfTargetProducts.Severity;
            if (summaryOfTargetProducts.Severity == "緊急")
            {
                workRow[Constants.SummaryTableColumn.EaseOfAttack] += "(+)深刻度が緊急";
            }

            foreach (string targetProductName in tableRepresentingPresenceOfTargetProduct.Keys)
            {
                workRow[targetProductName] = tableRepresentingPresenceOfTargetProduct[targetProductName];
            }
        }

        private static object CreateStringOfReleaseValueForTable(ReleaseExploitability ReleaseExploitability)
        {
            return ReleaseExploitability == null ? "" : ReleaseExploitability.Id.ToString() + "-" + ReleaseExploitability.Name;
        }

        private static void SetColumnsToAffectedTargetProductsTable(DataTable affectedTargetProductsTable)
        {
            affectedTargetProductsTable.Columns.Add("CVENumber");
            affectedTargetProductsTable.Columns.Add("Name");
            affectedTargetProductsTable.Columns.Add("CountOfRowsWithAtLeastOneArticleOrUrl");
            affectedTargetProductsTable.Columns.Add("ArticleUrl1");
            affectedTargetProductsTable.Columns.Add("DownloadTitle1");
            affectedTargetProductsTable.Columns.Add("DownloadUrl1");
            affectedTargetProductsTable.Columns.Add("ArticleUrl2");
            affectedTargetProductsTable.Columns.Add("DownloadTitle2");
            affectedTargetProductsTable.Columns.Add("DownloadUrl2");
            affectedTargetProductsTable.Columns.Add("ArticleUrl3");
            affectedTargetProductsTable.Columns.Add("DownloadTitle3");
            affectedTargetProductsTable.Columns.Add("DownloadUrl3");
            affectedTargetProductsTable.Columns.Add("ArticleUrl4");
            affectedTargetProductsTable.Columns.Add("DownloadTitle4");
            affectedTargetProductsTable.Columns.Add("DownloadUrl4");
            affectedTargetProductsTable.Columns.Add("Platform");
            affectedTargetProductsTable.Columns.Add("ImpactId");
            affectedTargetProductsTable.Columns.Add("Impact");
            affectedTargetProductsTable.Columns.Add("SeverityId");
            affectedTargetProductsTable.Columns.Add("Severity");
            affectedTargetProductsTable.Columns.Add("BaseScore");
            affectedTargetProductsTable.Columns.Add("TemporalScore");
            affectedTargetProductsTable.Columns.Add("EnvironmentScore");
            affectedTargetProductsTable.Columns.Add("VectorString");
            affectedTargetProductsTable.Columns.Add("Supersedence");
            affectedTargetProductsTable.Columns.Add("KnowledgeBaseId");
            affectedTargetProductsTable.Columns.Add("KnowledgeBaseUrl");
            affectedTargetProductsTable.Columns.Add("MonthlyKnowledgeBaseId");
            affectedTargetProductsTable.Columns.Add("MonthlyKnowledgeBaseUrl");
            affectedTargetProductsTable.Columns.Add("DownloadUrl");
            affectedTargetProductsTable.Columns.Add("DownloadTitle");
            affectedTargetProductsTable.Columns.Add("MonthlyDownloadUrl");
            affectedTargetProductsTable.Columns.Add("MonthlyDownloadTitle");
            affectedTargetProductsTable.Columns.Add("ArticleTitle1");
            affectedTargetProductsTable.Columns.Add("ArticleTitle2");
            affectedTargetProductsTable.Columns.Add("ArticleTitle3");
            affectedTargetProductsTable.Columns.Add("ArticleTitle4");
            affectedTargetProductsTable.Columns.Add("DoesRowOneHaveAtLeastOneArticleOrUrl");
            affectedTargetProductsTable.Columns.Add("DoesRowTwoHaveAtLeastOneArticleOrUrl");
            affectedTargetProductsTable.Columns.Add("DoesRowThreeHaveAtLeastOneArticleOrUrl");
            affectedTargetProductsTable.Columns.Add("DoesRowFourHaveAtLeastOneArticleOrUrl");
        }

        private static void SetColumnsToSummaryTable(List<string> targetProducts, DataTable summaryTable)
        {
            summaryTable.Columns.Add(Constants.SummaryTableColumn.CveNumber);
            summaryTable.Columns.Add(Constants.SummaryTableColumn.CveTitle);
            summaryTable.Columns.Add(Constants.SummaryTableColumn.Description);
            summaryTable.Columns.Add(Constants.SummaryTableColumn.Severity);
            summaryTable.Columns.Add(Constants.SummaryTableColumn.PubliclyDisclosed);
            summaryTable.Columns.Add(Constants.SummaryTableColumn.Exploited);
            summaryTable.Columns.Add(Constants.SummaryTableColumn.LatestReleaseExploitability);
            summaryTable.Columns.Add(Constants.SummaryTableColumn.OlderReleaseExploitability);
            summaryTable.Columns.Add(Constants.SummaryTableColumn.DenialOfService);
            summaryTable.Columns.Add(Constants.SummaryTableColumn.VectorString, Type.GetType("System.String"));
            summaryTable.Columns.Add(Constants.SummaryTableColumn.BaseScore, Type.GetType("System.Double"));
            summaryTable.Columns.Add(Constants.SummaryTableColumn.TemporalScore, Type.GetType("System.Double"));
            foreach (var targetProduct in targetProducts)
            {
                summaryTable.Columns.Add(targetProduct);
            }
            summaryTable.Columns.Add(Constants.SummaryTableColumn.EaseOfAttack);
            summaryTable.Columns.Add(Constants.SummaryTableColumn.Remarks);
        }

        private static void SetAffectedTargetProductValuesToRow(AffectedProduct affectedTargetProduct, DataRow affectedTargetProductRow)
        {
            affectedTargetProductRow["Name"] = affectedTargetProduct.Name;
            affectedTargetProductRow["Platform"] = affectedTargetProduct.Platform;
            affectedTargetProductRow["ImpactId"] = affectedTargetProduct.ImpactId;
            affectedTargetProductRow["Impact"] = affectedTargetProduct.Impact;
            affectedTargetProductRow["SeverityId"] = affectedTargetProduct.SeverityId;
            affectedTargetProductRow["Severity"] = affectedTargetProduct.Severity;
            affectedTargetProductRow["BaseScore"] = affectedTargetProduct.BaseScore;
            affectedTargetProductRow["TemporalScore"] = affectedTargetProduct.TemporalScore;
            affectedTargetProductRow["EnvironmentScore"] = affectedTargetProduct.EnvironmentScore;
            affectedTargetProductRow["VectorString"] = affectedTargetProduct.VectorString;
            affectedTargetProductRow["Supersedence"] = affectedTargetProduct.Supersedence;
            affectedTargetProductRow["KnowledgeBaseId"] = affectedTargetProduct.KnowledgeBaseId;
            affectedTargetProductRow["KnowledgeBaseUrl"] = affectedTargetProduct.KnowledgeBaseUrl;
            affectedTargetProductRow["MonthlyKnowledgeBaseId"] = affectedTargetProduct.MonthlyKnowledgeBaseId;
            affectedTargetProductRow["MonthlyKnowledgeBaseUrl"] = affectedTargetProduct.MonthlyKnowledgeBaseUrl;
            affectedTargetProductRow["DownloadUrl"] = affectedTargetProduct.DownloadUrl;
            affectedTargetProductRow["DownloadTitle"] = affectedTargetProduct.DownloadTitle;
            affectedTargetProductRow["MonthlyDownloadUrl"] = affectedTargetProduct.MonthlyDownloadUrl;
            affectedTargetProductRow["MonthlyDownloadTitle"] = affectedTargetProduct.MonthlyDownloadTitle;
            affectedTargetProductRow["ArticleTitle1"] = affectedTargetProduct.ArticleTitle1;
            affectedTargetProductRow["ArticleUrl1"] = affectedTargetProduct.ArticleUrl1;
            affectedTargetProductRow["DownloadTitle1"] = affectedTargetProduct.DownloadTitle1;
            affectedTargetProductRow["DownloadUrl1"] = affectedTargetProduct.DownloadUrl1;
            affectedTargetProductRow["DoesRowOneHaveAtLeastOneArticleOrUrl"] = affectedTargetProduct.DoesRowOneHaveAtLeastOneArticleOrUrl;
            affectedTargetProductRow["ArticleTitle2"] = affectedTargetProduct.ArticleTitle2;
            affectedTargetProductRow["ArticleUrl2"] = affectedTargetProduct.ArticleUrl2;
            affectedTargetProductRow["DownloadTitle2"] = affectedTargetProduct.DownloadTitle2;
            affectedTargetProductRow["DownloadUrl2"] = affectedTargetProduct.DownloadUrl2;
            affectedTargetProductRow["DoesRowTwoHaveAtLeastOneArticleOrUrl"] = affectedTargetProduct.DoesRowTwoHaveAtLeastOneArticleOrUrl;
            affectedTargetProductRow["ArticleTitle3"] = affectedTargetProduct.ArticleTitle3;
            affectedTargetProductRow["ArticleUrl3"] = affectedTargetProduct.ArticleUrl3;
            affectedTargetProductRow["DownloadTitle3"] = affectedTargetProduct.DownloadTitle3;
            affectedTargetProductRow["DownloadUrl3"] = affectedTargetProduct.DownloadUrl3;
            affectedTargetProductRow["DoesRowThreeHaveAtLeastOneArticleOrUrl"] = affectedTargetProduct.DoesRowThreeHaveAtLeastOneArticleOrUrl;
            affectedTargetProductRow["ArticleTitle4"] = affectedTargetProduct.ArticleTitle4;
            affectedTargetProductRow["ArticleUrl4"] = affectedTargetProduct.ArticleUrl4;
            affectedTargetProductRow["DownloadTitle4"] = affectedTargetProduct.DownloadTitle4;
            affectedTargetProductRow["DownloadUrl4"] = affectedTargetProduct.DownloadUrl4;
            affectedTargetProductRow["DoesRowFourHaveAtLeastOneArticleOrUrl"] = affectedTargetProduct.DoesRowFourHaveAtLeastOneArticleOrUrl;
            affectedTargetProductRow["CountOfRowsWithAtLeastOneArticleOrUrl"] = affectedTargetProduct.CountOfRowsWithAtLeastOneArticleOrUrl;
        }

        private static void CheckIfEqualToAssignedData(AffectedProduct summaryOfTargetProducts, AffectedProduct affectedTargetProduct)
        {
            if (affectedTargetProduct.VectorString != null
                && summaryOfTargetProducts.VectorString != null
                && !summaryOfTargetProducts.VectorString.Equals(affectedTargetProduct.VectorString))
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

            if (!String.IsNullOrEmpty(summaryOfTargetProducts.Severity) && !summaryOfTargetProducts.Severity.Equals(affectedTargetProduct.Severity))
            {
                summaryOfTargetProducts.Severity = default(string);
                Console.WriteLine("対象製品のSeverityの中に一致しないものがあります");
            }
        }

        private static void CheckIfContainToProductName(string affectedTargetProductName, Hashtable tableRepresentingPresenceOfTargetProduct)
        {
            ArrayList targetProductNameList = new ArrayList(tableRepresentingPresenceOfTargetProduct.Keys);
            foreach (string targetProductName in targetProductNameList)
            {
                if (affectedTargetProductName.Contains(targetProductName))
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
            workRow[Constants.SummaryTableColumn.CveTitle] = sg.CveTitle;
            workRow[Constants.SummaryTableColumn.Description] = sg.Description
                .Replace("<p>", "")
                .Replace("</p>", Environment.NewLine);
            workRow[Constants.SummaryTableColumn.PubliclyDisclosed] = sg.PubliclyDisclosed;
            
            // 悪用ありの場合は攻撃しやすさ列へ(+)として設定
            workRow[Constants.SummaryTableColumn.Exploited] = sg.Exploited;
            if (sg.Exploited == "あり")
            {
                workRow[Constants.SummaryTableColumn.EaseOfAttack] += "(+)悪用あり" + Environment.NewLine;
            }

            // 最新及び過去のソフトウェアリリース情報を作成して格納する
            var LatestRelease = CreateStringOfReleaseValueForTable(sg.ExploitabilityAssessment.LatestReleaseExploitability);
            var OlderRelease = CreateStringOfReleaseValueForTable(sg.ExploitabilityAssessment.OlderReleaseExploitability);
            workRow[Constants.SummaryTableColumn.LatestReleaseExploitability] = LatestRelease;
            workRow[Constants.SummaryTableColumn.OlderReleaseExploitability] = OlderRelease;

            // サービス拒否を日本語表記へ変換する。APIの表記は以下の通り。
            // 対象外：<DenialOfServiceExploitability i:nil="true"/>
            // 永続的：<DenialOfServiceExploitability>永続的</DenialOfServiceExploitability>
            workRow[Constants.SummaryTableColumn.DenialOfService] = String.IsNullOrEmpty((string)sg.ExploitabilityAssessment.DenialOfServiceExploitability) ? "対象外" : sg.ExploitabilityAssessment.DenialOfServiceExploitability;
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
                Constants.ProductName.Win_2012_R2_SeverCore,
                Constants.ProductName.Win_2012_R2,
                Constants.ProductName.Win_2016_ServerCore,
                Constants.ProductName.Win_2016,
                Constants.ProductName.MS_NET_Framework_4_x,
                Constants.ProductName.MS_SQL_Server_2014_x,
                Constants.ProductName.IE_11
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
            return @"ADV190006 CVE-2019-0595 CVE-2019-0596 CVE-2019-0597 CVE-2019-0654 CVE-2019-0598 CVE-2019-0599 CVE-2019-0656 CVE-2019-0657 CVE-2019-0600 CVE-2019-0601 CVE-2019-0659 CVE-2019-0660 CVE-2019-0602 CVE-2019-0606 CVE-2019-0661 CVE-2019-0662 CVE-2019-0664 CVE-2019-0613 CVE-2019-0676 CVE-2019-0615 CVE-2019-0616 CVE-2019-0618 CVE-2019-0619 CVE-2019-0621 CVE-2019-0623 CVE-2019-0625 CVE-2019-0626 CVE-2019-0627 CVE-2019-0628 CVE-2019-0630 CVE-2019-0631 CVE-2019-0632 CVE-2019-0633 CVE-2019-0635 CVE-2019-0636"; // 2019/02
            //return @"CVE-2019-0536 CVE-2019-0541 CVE-2019-0543 CVE-2019-0545 CVE-2019-0549 CVE-2019-0551 CVE-2019-0552 CVE-2019-0554 CVE-2019-0555 CVE-2019-0569 CVE-2019-0570 CVE-2019-0571 CVE-2019-0572 CVE-2019-0573 CVE-2019-0574 CVE-2019-0575 CVE-2019-0576 CVE-2019-0577 CVE-2019-0578 CVE-2019-0579 CVE-2019-0580 CVE-2019-0581 CVE-2019-0582 CVE-2019-0583 CVE-2019-0584 CVE-2018-8653"; // 2019/01
            //return @"CVE-2018-8477 CVE-2018-8514 CVE-2018-8517 CVE-2018-8540 CVE-2018-8596 CVE-2018-8599 CVE-2018-8611 CVE-2018-8612 CVE-2018-8617 CVE-2018-8618 CVE-2018-8619 CVE-2018-8622 CVE-2018-8624 CVE-2018-8625 CVE-2018-8626 CVE-2018-8629 CVE-2018-8631 CVE-2018-8634 CVE-2018-8639 CVE-2018-8641 CVE-2018-8643 CVE-2018-8595 ADV180029"; // 2018/12
            //return @"ADV180028 ADV990001 CVE-2018-8256 CVE-2018-8407 CVE-2018-8408 CVE-2018-8415 CVE-2018-8417 CVE-2018-8450 CVE-2018-8471 CVE-2018-8476 CVE-2018-8485 CVE-2018-8542 CVE-2018-8543 CVE-2018-8544 CVE-2018-8547 CVE-2018-8549 CVE-2018-8550 CVE-2018-8552 CVE-2018-8553 CVE-2018-8555 CVE-2018-8556 CVE-2018-8557 CVE-2018-8561 CVE-2018-8562 CVE-2018-8563 CVE-2018-8564 CVE-2018-8565 CVE-2018-8566 CVE-2018-8584 CVE-2018-8588 CVE-2018-8589"; // 2018/11
            //return @"CVE-2018-8333 CVE-2018-8438 CVE-2018-8453 CVE-2018-8490"; // サービス拒否の対象外と永続的の２種, 悪用ありなし, 深刻度が重要と緊急
            //return @"CVE-2018-8333 CVE-2018-8411 CVE-2018-8413 CVE-2018-8320 CVE-2018-8330 CVE-2018-8423 CVE-2018-8427 CVE-2018-8432 CVE-2018-8453 CVE-2018-8472 CVE-2018-8481 CVE-2018-8482 CVE-2018-8484 CVE-2018-8486 CVE-2018-8489 CVE-2018-8490 CVE-2018-8492 CVE-2018-8493 CVE-2018-8494 CVE-2018-8495 CVE-2018-8497"; // 2018/10
            //return @"CVE-2018-8308 CVE-2018-83080 CVE-2018-8176 CVE-2018-8311 ADV113456 正規表現と一致しない";
        }
    }
}
