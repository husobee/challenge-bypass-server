package server

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

func (c *Server) initDynamo() {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := dynamodb.New(sess, &aws.Config{
		Region: aws.String("us-west-2"),
	})

	c.dynamo = svc
}

func (c *Server) redeemTokenV2(issuer *Issuer, preimageTxt []byte, payload string) error {
	redemption := RedemptionV2{
		IssuerID: issuer.ID,
		ID:       string(preimageTxt),
		Payload:  payload,
		TTL:      issuer.ExpiresAt.Unix(),
	}

	av, err := dynamodbattribute.MarshalMap(redemption)
	if err != nil {
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(issuer) AND attribute_not_exists(nonce)"),
		TableName:           aws.String("redemption"),
	}

	_, err = c.dynamo.PutItem(input)
	if err != nil {
		return err
	}

	return nil
}
