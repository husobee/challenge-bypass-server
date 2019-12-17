package server

import "github.com/robfig/cron/v3"

func SetupCronTasks() {
	c := cron.New()
	c.AddFunc("30 * * * *", func() {
		
	});
}
