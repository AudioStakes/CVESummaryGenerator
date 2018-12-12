# 手順
1. MicroSoftセキュリティ更新プログラムガイド（下記URL）へ接続し、Excelダウンロード。
	* https://portal.msrc.microsoft.com/ja-jp/security-guidance
	* 日付範囲に、先月のパッチリリース日より後～今月のパッチリリース日より後を指定
	* 「表示:  □詳細 □深刻度 □影響度」のチェックボックス全てにチェックを入れる
1. Excelを開き、以下の通りに「製品」と「プラットフォーム」の２列をフィルタリング。
	* 「製品」
		* Windows Server 2008 for 32-bit Systems Service Pack 2
		* Windows Server 2012 R2 (Server Core installation)
		* Windows Server 2016 (Server Core installation)
		* Internet Explorer 11
		* ※Microsoft Edge, Internet Explorer 9,10は不要
		* ※.NETとMSSQLは詳細ファイル参照
	* 「プラットフォーム」
		* Windows Server 2008 for 32-bit Systems Service Pack 2
		* Windows Server 2012 R2
		* Windows Server 2016
		* (空白セル)
1. ＣＶＥ列を重複削除して対象ＣＶＥを特定
