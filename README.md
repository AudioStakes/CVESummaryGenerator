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
		* Microsoft Edge
		* Internet Explorer 11
		* Internet Explorer 10（不要？）
		* Internet Explorer 9（不要？）
	* 「プラットフォーム」
		* Windows Server 2008 for 32-bit Systems Service Pack 2
		* Windows Server 2012 R2
		* Windows Server 2016
		* (空白セル)
1. ＣＶＥを特定するため、以下の列の重複行を削除
	* 「詳細」
1. サーバーごとの手動ダウンロードファイルを特定するため、以下の列の重複行を削除
	* 「製品」、「プラットフォーム」、「記事」
1. 以下、各ＣＶＥごとにまとめ作成
