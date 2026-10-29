# 驗證證據怎麼讀

JSON是供程式讀取的結構化資料。先讀[名詞與驗證編號](../../名詞與代碼對照.md)，再看檔案；不要從一個代碼推測是否通過。

- `守恆驗收.json`：主實驗1350次與基準600樣本的守恆統計；重用30次另列。
- `完整驗證計算_v8.json`：V1–V11各檢查的實際計算與個別診斷；版本V8與第八項檢查不同。
- `原生PFM重算比對.json`：單次實驗績效量測（PFM）指一次模擬的績效量測值，檢查是否與原始計數一致。
- `導航與調度驗收.json`：路徑、單行與人員到站支援的有限測試。
- `Dashboard_ESG重算.json`：即時儀表板的能耗與減碳獨立重算，並非六日平均。
- `影片完整性.json`：影格、模擬時間與影片長度。
- `簡報圖表數值核對.json`／`審查數據核對.json`：簡報數字與審查敘事對照。

常見欄名：`mean`平均、`low/high`信賴下界／上界、`n`樣本數、`pass`通過、`relative_halfwidth_pct`相對信賴半寬（百分比）、`max_abs_difference`最大絕對差。任何「通過」都只在檔案敘明的樣本和判定範圍成立。

## 公開模型驗收

[公開模型驗收.json](公開模型驗收.json)記錄四個原生模型、同名結果資料庫的安全掃描、公開前後七天數值比對，以及全新FlexSim視窗的實際開啟結果。`regression`是同種子重跑核對，`checkpoints_seconds`是檢查時刻（秒），`numeric_values_compared`是逐項比對的數值數量，`fresh_gui`是全新軟體視窗驗收；`main_experiments_complete`為1350次主實驗，`additional_precision_complete`為570次新增精度實驗。資料庫各表的`rows`為列數，`identical`表示每個值均與原件相同；`sha256`是檔案指紋，不是金鑰。

## 中文名稱與代號核對

[中文名稱代號核對.json](中文名稱代號核對.json)記錄正文與簡報的中文名稱調整範圍。`chart_numeric_values_unchanged`表示20個圖表數值保持一致，`equipment_heatmap_values_unchanged`表示28個設備熱圖數值一致；`unchanged_model_database_and_csv_files`列出本次以檔案指紋確認未改動的模型、資料庫與原始資料。
