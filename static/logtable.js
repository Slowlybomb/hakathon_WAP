// logtable.js

// Detail expansion HTML builder
function formatDetails(rowData) {
    return `
        <b>Full User Agent:</b> ${rowData[7]}<br>
        <b>Request Type:</b> ${rowData[2]}<br>
        <b>Requested Resource:</b> ${rowData[3]}<br>
        <b>Status Code:</b> ${rowData[4]}<br>
        <b>Size (Bytes):</b> ${rowData[5]}<br>
        <b>Bot:</b> ${rowData[8]}
    `;
}

$(document).ready(function () {
    const table = $('#logTable').DataTable({
        dom: 'Bfrtip',
        buttons: ['copy', 'csv', 'excel', 'print'],
        pageLength: 25,
        scrollX: true,
        columnDefs: [{ orderable: false, targets: 0 }],
        createdRow: function (row, data, dataIndex) {
            const code = parseInt(data[4]);
            if (code >= 500) {
                $(row).css('background-color', '#f8d7da'); // server error
            } else if (code >= 400) {
                $(row).css('background-color', '#fff3cd'); // client error
            } else if (code >= 300) {
                $(row).css('background-color', '#d1ecf1'); // redirect
            } else if (code >= 200) {
                $(row).css('background-color', '#d4edda'); // success
            }
        }
    });

    // Toggle row details on click
    $('#logTable tbody').on('click', 'td.details-control', function () {
        const tr = $(this).closest('tr');
        const row = table.row(tr);

        if (row.child.isShown()) {
            row.child.hide();
            $(this).html('▶');
        } else {
            row.child(formatDetails(row.data())).show();
            $(this).html('▼');
        }
    });
});
