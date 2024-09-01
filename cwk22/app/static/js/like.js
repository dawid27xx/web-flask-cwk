function like(postId) {
    $.ajax({
        url: '/like/' + postId,
        type: 'POST',
        success: function(response) {
            if (response.status === 'success') {
                document.getElementById('like-count-' + postId).innerText = response.like_count;
                document.getElementById('like-count-' + postId).style.color = response.color;
            }
        },
        error: function(error) {
            console.error('Error:', error);
        }
    });
};