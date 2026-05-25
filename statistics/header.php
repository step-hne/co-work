<!DOCTYPE html>
<html>

<head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    
    <title>Lead Report!</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
    <meta http-equiv="Pragma" content="no-cache" />
    <meta http-equiv="Expires" content="0" />
    <link href="../favicon.ico" rel="icon" type="image/x-icon" />
    <link rel="stylesheet" href="../dist/bootstrap.min.css" type="text/css" media="all">
    <link href="../dist/jquery.bootgrid.css" rel="stylesheet" />
    <link href="../dist/div.table.css" rel="stylesheet" />
    <link rel="stylesheet" href="//cdn.datatables.net/1.10.19/css/dataTables.bootstrap.min.css">
    <link href="//cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css" rel="stylesheet">
    <link href="//fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet" type="text/css">
    <link rel="stylesheet" href="../dist/flags.css">
    <script src="../dist/jquery-1.11.1.min.js"></script>
    <script src="../dist/bootstrap.min.js"></script>
    <script src="../dist/jquery.bootgrid.min.js"></script>
    <script src="//cdn.datatables.net/1.10.19/js/jquery.dataTables.min.js"></script>
    <script src="//unpkg.com/sweetalert/dist/sweetalert.min.js"></script>
    <script src="//cdn.jsdelivr.net/npm/sweetalert2@8"></script>
    <link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/1.4.1/css/bootstrap-datepicker3.css"/>
    <script src="../dist/FileSaver.min.js"></script>
    <script src="../dist/Blob.min.js"></script>
    <script src="../dist/xls.core.min.js"></script>
    <script src="../dist/tableexport.js"></script>

    <style>
	    input[type="text"]
	    {
	        font-family:consolas;
	    }
    .rg-source{margin:0;font-size:.75em;text-align:right}.rg-source .pre-colon{text-transform:uppercase}.rg-source .post-colon{font-weight:bold}::-webkit-input-placeholder{color:#808080;text-align:left}:-moz-placeholder{color:#808080;text-align:left}
        @media only screen and (max-width: 760px),
        (min-device-width: 768px) and (max-device-width: 1024px) {
            .panel_m {
                display: block;
                width: max-content;
            }
        }
        
        .search {
            max-width: 350px;
        }
        
        button {
            outline: none!important
        }
        
        button:focus {
            box-shadow: none;
            outline: 0
        }
        
        button:active {
            outline: 0
        }
        body {
            padding-top: 70px;
        }
        #notifications {cursor: pointer;
            position: fixed;
            right: 0px;
            z-index: 9999;
            bottom: 0px;
            margin-bottom: 22px;
            margin-right: 15px;
            max-width: 300px;}
        .fon{overflow: hidden;
            white-space: pre-line;
            z-index: 1;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            max-width: auto;
            text-overflow: ellipsis;}
@import url('https://fonts.googleapis.com/css?family=Codystar:300&display=swap');

.neons {
   font-family: 'Codystar';
}
#infoya {cursor: pointer;
  position: absolute;
  right: 16px;
            margin-bottom: 22px;
            margin-right: 15px;
            max-width: 300px;}
        .fon{overflow: hidden;
            white-space: pre-line;
            z-index: 1;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            max-width: auto;
            text-overflow: ellipsis;}
            .fixed {
    position:fixed;
    width:100%;
    top:10;
    left:0;
}
.neons {
   font-weight: bold;
  -webkit-animation: glow 2s ease-in-out infinite alternate;
  -moz-animation: glow 2s ease-in-out infinite alternate;
  animation: glow 2s ease-in-out infinite alternate;
}

@-webkit-keyframes glow {
     from {
      color: #fff;
    text-shadow: 0 0 1px #4c75a3, 0 0 2px #4c75a3, 0 0 3px #4c75a3, 0 0 4px #4c75a3, 0 0 5px #4c75a3, 0 0 6px #4c75a3, 0 0 7px #4c75a3, 0 0 90px #4c75a3;
  }
  
  to {
     color: gray;
    text-shadow: 0 0 2px #4c75a3, 0 0 3px #4c75a3, 0 0 4px #4c75a3, 0 0 5px #4c75a3, 0 0 6px #4c75a3, 0 0 7px #4c75a3, 0 0 8px #4c75a3, 0 1 9px #4c75a3;
  }
}
/* mobile phone */
@media all and (max-width: 768px) {
    #notifications{ display: none !important;
}
    #ea{ display: none !important;
}
}

/* ── Tailwind slim-fit table ─────────────────── */
body, .table, .form-control, .btn, .panel, .navbar,
input, select, textarea {
    font-family: 'Inter', system-ui, -apple-system, sans-serif !important;
}
.table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
    border: 0;
    color: #111827;
}
.table > thead > tr > th {
    height: 34px;
    padding: 0 12px !important;
    font-size: 11px;
    font-weight: 600;
    color: #374151;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    background: #f3f4f6 !important;
    border-bottom: 1px solid #d1d5db !important;
    border-top: 0 !important;
    white-space: nowrap;
    text-align: left;
}
.table > tbody > tr > td,
.table > tfoot > tr > td {
    padding: 6px 12px !important;
    font-size: 12.5px;
    line-height: 1.4;
    font-weight: 400;
    color: #111827;
    vertical-align: middle;
    border-top: 0 !important;
    border-bottom: 1px solid #f3f4f6 !important;
}
.table > tbody > tr:last-child > td {
    border-bottom: 0 !important;
}
.table > tbody > tr:hover > td {
    background-color: #f9fafb !important;
}
.table-striped > tbody > tr:nth-of-type(odd) > td {
    background: transparent !important;
}
.panel {
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    box-shadow: 0 1px 3px rgba(0,0,0,.06), 0 4px 12px rgba(0,0,0,.05);
}
input:focus, select:focus, textarea:focus, .form-control:focus {
    color: #111827;
}
.panel-heading {
    background: #f9fafb !important;
    border-bottom: 1px solid #e5e7eb !important;
    border-radius: 8px 8px 0 0 !important;
    padding: 8px 12px;
}
/* ── div-layout slim-fit (click/ & perfomace.click/) ── */
.method .list-header .header {
    font-size: 11px !important;
    font-weight: 600 !important;
    color: #374151 !important;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    background: #f3f4f6 !important;
    padding: 6px 12px !important;
    border-bottom: 1px solid #d1d5db;
}
.method .cell {
    font-size: 12.5px !important;
    color: #111827 !important;
    padding: 5px 12px !important;
    line-height: 1.4;
}
.method .cell code {
    font-size: 11.5px;
    color: #2563eb;
}
.method [class^="row"],
.method [class*=" row"] {
    border-bottom: 1px solid #f3f4f6 !important;
}
.method [class^="row"]:hover,
.method [class*=" row"]:hover {
    background-color: #f9fafb !important;
}
/* ─────────────────────────────────────────────── */
#logout-toast{position:fixed;bottom:20px;right:20px;background:rgba(41,43,44,.88);color:#fff;padding:7px 15px;border-radius:6px;font-size:12px;font-weight:600;z-index:99999;opacity:0;pointer-events:none;transition:opacity .2s;box-shadow:0 2px 8px rgba(0,0,0,.22)}
#logout-toast.show{opacity:1}
    </style></head>

<body>
