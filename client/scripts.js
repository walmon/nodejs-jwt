
		$(document).ready(function(){
			var bearerToken = "";
			$('#btn-get-data').click(function(){
				var token = $("#token").val();
				var bearerToken = "bearer " + token;
				$.ajax({url:'http://localhost:3001/me',
					beforeSend:function(request){
						request.setRequestHeader('authorization', bearerToken);
					}}).done(function(data){
						$('#result-get').html('ok: ' + JSON.stringify(data));
				}).fail(function(err){
					$('#result-get').html("Error al consultar el API: "+ err.statusText);
				});
			});
			$("#signin").submit(function(e){
				e.preventDefault();

				var args = $(this).serialize();

				$.ajax({url:'http://localhost:3001/signin', method:'post', data:args}).done(function(data){
					$('#result-signin').html('ok: ' + JSON.stringify(data));
				}).fail(function(err){
					$('#result-signin').html("Error al consultar el API: "+ err.statusText);
				})
			});
			$("#login").submit(function(e){
				e.preventDefault();

				var args = $(this).serialize();

				$.ajax({url:'http://localhost:3001/login', method:'post', data:args}).done(function(data){
					$('#result-login').html('ok: ' + JSON.stringify(data));
				}).fail(function(err){
					$('#result-login').html("Error al consultar el API: "+ err.statusText);
				})
			});
		});