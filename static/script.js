var old_query_value = "";

function selectSearch() {
	document.searchForm.query.focus();
}

function onSearch(query) {
	if (old_query_value == "") {
		if (query.length > 5) {
			old_query_value = query;
			document.searchForm.submit();
		} else {
			old_query_value = query;
		}
	}
}
