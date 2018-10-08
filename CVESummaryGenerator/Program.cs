﻿using System;
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
                    || n.Name.Contains(Constants.ProductName.MS_NET_Framework_4_x)
                    || n.Name.Contains(Constants.ProductName.MS_SQL_Server_2014_x)
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
                    // affectedTargetProductに対応する行を作成
                    DataRow affectedTargetProductRow = affectedTargetProductsTable.NewRow();

                    // CVENumberを格納
                    affectedTargetProductRow["CveNumber"] = cve;

                    // affectedTargetProductの値を行へセット
                    SetAffectedTargetProductValuesToRow(affectedTargetProduct, affectedTargetProductRow);

                    // Rows.Addメソッドを使ってデータを追加
                    affectedTargetProductsTable.Rows.Add(affectedTargetProductRow);

                    // ＣＶＥの影響対象製品と一致する目的製品を確認する
                    CheckIfContainToProductName(affectedTargetProduct.Name, TableRepresentingPresenceOfTargetProduct);

                    // TODO:affectedTargetProductごとにまとめＣＶＥファイルを作成する。
                    // ダウンロードＵＲＬなどが載っていたほうがわかりやすいため。

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

                // Rows.Addメソッドを使ってデータを追加
                summaryTable.Rows.Add(workRow);
            }

            // summaryTableの値を出力する
            OutputValuesOfTheSummaryTable(summaryTable);

            // ＣＳＶファイル保存先の完全パスを取得
            string csvPath = GetFullPathWithCurrentDirectoryAndCurrentTimeAsCSVFileName();

            // CSVコンバーターを呼び出す
            DatatableToCSVConverter csv = new DatatableToCSVConverter();

            // DataTableをCSVで保存する
            csv.ConvertDataTableToCsv(summaryTable, csvPath, true);
            csv.ConvertDataTableToCsv(affectedTargetProductsTable, csvPath + "_affectedTargetProducts.csv", true);

            Console.ReadLine();
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
            workRow[Constants.SummaryTableColumn.Severity] = summaryOfTargetProducts.Severity;
            foreach (string targetProductName in tableRepresentingPresenceOfTargetProduct.Keys)
            {
                workRow[targetProductName] = tableRepresentingPresenceOfTargetProduct[targetProductName];
            }
        }

        private static object CreateStringOfReleaseValueForTable(ReleaseExploitability ReleaseExploitability)
        {
            return ReleaseExploitability.Id.ToString() + "-" + ReleaseExploitability.Name;

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
            summaryTable.Columns.Add(Constants.SummaryTableColumn.VectorString);
            summaryTable.Columns.Add(Constants.SummaryTableColumn.BaseScore, Type.GetType("System.Double"));
            summaryTable.Columns.Add(Constants.SummaryTableColumn.TemporalScore, Type.GetType("System.Double"));
            foreach (var targetProduct in targetProducts)
            {
                summaryTable.Columns.Add(targetProduct);
            }
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
            workRow[Constants.SummaryTableColumn.Exploited] = sg.Exploited;

            // 最新及び過去のソフトウェアリリース情報を作成して格納する
            var LatestRelease = CreateStringOfReleaseValueForTable(sg.ExploitabilityAssessment.LatestReleaseExploitability);
            var OlderRelease = CreateStringOfReleaseValueForTable(sg.ExploitabilityAssessment.OlderReleaseExploitability);
            workRow[Constants.SummaryTableColumn.LatestReleaseExploitability] = LatestRelease;
            workRow[Constants.SummaryTableColumn.OlderReleaseExploitability] = OlderRelease;
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
                Constants.ProductName.MS_NET_Framework_4_x,
                Constants.ProductName.MS_SQL_Server_2014_x,

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
            return @"CVE-2018-8421 CVE-2017-8516 CVE-2018-8392 CVE-2018-8393 ADV180022 CVE-2018-0965 CVE-2018-8271 CVE-2018-8332 CVE-2018-8335 CVE-2018-8336 CVE-2018-8410 CVE-2018-8419 CVE-2018-8420 CVE-2018-8421 CVE-2018-8424 CVE-2018-8433 CVE-2018-8434 CVE-2018-8435 CVE-2018-8438 CVE-2018-8439 CVE-2018-8440 CVE-2018-8442 CVE-2018-8443 CVE-2018-8444 CVE-2018-8446 CVE-2018-8449 CVE-2018-8455 CVE-2018-8462 CVE-2018-8468 CVE-2018-8475";
            //return @"CVE-2018-8308 CVE-2018-83080 CVE-2018-8176 CVE-2018-8311 ADV113456 正規表現と一致しない";
        }
    }
}
