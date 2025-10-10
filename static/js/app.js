$(document).ready(function(){
  var table = $('#alerts').DataTable();
  function load(){
    $.getJSON('/alerts', function(data){
      table.clear();
      data.forEach(function(r){
        table.row.add([r.id, r.timestamp, r.src_ip, r.url, r.attack, r.confidence]);
      });
      table.draw();
    });
  }
  $('#refresh').click(load);
  load();
});
