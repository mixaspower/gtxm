require('dotenv').config();
const axios = require('axios');

// Function to get 50 random video URLs from YouTube
async function getRandomVideos() {
    const keywords = ['funny', 'weird', 'new', 'amazing', 'technology', 'random'];
    const chosenKeyword = keywords[Math.floor(Math.random() * keywords.length)];

    const API_URL = 'https://www.googleapis.com/youtube/v3/search';

    try {
        const response = await axios.get(API_URL, {
            params: {
                part: 'snippet',
                q: chosenKeyword,
                type: 'video',
                maxResults: 50,
                key: process.env.YOUTUBE_API_KEY,
            },
        });

        if (response.data.items.length > 0) {
            console.log('50 Random YouTube Video URLs:');
            response.data.items.forEach((item, index) => {
                const videoId = item.id.videoId;
                console.log(`${index + 1}: https://www.youtube.com/watch?v=${videoId}`);
            });
        } else {
            console.log('No videos found.');
        }
    } catch (error) {
        console.error('Error fetching videos:', error);
    }
}

// Call the function
getRandomVideos();
